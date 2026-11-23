# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.

"""
Synchronous entry points for the optional disaster recovery restore contract.

These helpers complement, but never replace, the native
``client.snapshot.restore`` API. Callers that do not need preflight approval
keep using the native method directly; callers that must only restore an
approved snapshot into temporary indices go through :func:`plan_restore` and
:func:`execute_restore`.
"""

from typing import Any, List, Mapping, Optional, Sequence

from ._restore_contract import (
    RestorePlan,
    RestoreReceipt,
    SnapshotView,
    build_receipt,
    build_restore_plan,
    ensure_approved,
    revalidate_plan,
)

__all__ = [
    "load_snapshot_view",
    "plan_restore",
    "revalidate_restore",
    "execute_restore",
]


def load_snapshot_view(client: Any, repository: str, snapshot: str) -> SnapshotView:
    """Fetch and interpret a single snapshot through the native snapshot API."""
    response = client.snapshot.get(repository=repository, snapshot=snapshot)
    return SnapshotView.from_response(repository, response, snapshot)


def plan_restore(
    client: Any,
    *,
    repository: str,
    snapshot: str,
    target_prefix: str,
    include_indices: Optional[Sequence[str]] = None,
    exclude_indices: Optional[Sequence[str]] = None,
    rename_map: Optional[Mapping[str, str]] = None,
    include_global_state: bool = False,
    extra_body: Optional[Mapping[str, Any]] = None,
    params: Optional[Mapping[str, Any]] = None,
    headers: Optional[Mapping[str, str]] = None,
) -> RestorePlan:
    """Preflight: resolve identity, filtered sources and frozen rename targets."""
    view = load_snapshot_view(client, repository, snapshot)
    return build_restore_plan(
        view,
        target_prefix=target_prefix,
        include_indices=include_indices,
        exclude_indices=exclude_indices,
        rename_map=rename_map,
        include_global_state=include_global_state,
        extra_body=extra_body,
        params=params,
        headers=headers,
    )


def revalidate_restore(client: Any, plan: RestorePlan) -> List[str]:
    """Re-check an existing plan against the current catalog; returns drift."""
    view = load_snapshot_view(client, plan.repository, plan.snapshot)
    return revalidate_plan(plan, view)


def execute_restore(client: Any, plan: RestorePlan) -> RestoreReceipt:
    """
    Execute an approved plan. The snapshot is re-read and the approval is
    re-validated before any restore request is sent; the request uses only the
    parameters captured at approval time.
    """
    view = load_snapshot_view(client, plan.repository, plan.snapshot)
    request = ensure_approved(plan, view)
    raw_response = client.snapshot.restore(
        repository=request.repository,
        snapshot=request.snapshot,
        body=request.body,
        params=request.params or None,
        headers=request.headers or None,
    )
    return build_receipt(plan, raw_response)
