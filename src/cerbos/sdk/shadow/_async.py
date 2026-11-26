# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Optional shadow checking client.

The shadow client wraps an *approved* in-memory engine and a *candidate*
in-memory engine.  Every authorization call is served from the approved engine,
so the business always enforces the approved result.  The same input is also
sent to the candidate engine in the background; its response is compared with
the approved one for audit purposes only.

Candidate calls are bounded by a timeout and isolated so that a slow or broken
candidate policy can never delay or fail the real response.  When the candidate
does not answer in time (or raises), the comparison is recorded as
``INCONCLUSIVE`` rather than guessed.
"""

import logging
import threading
import uuid
from collections.abc import Sequence

import anyio

from cerbos.sdk.model import (
    CheckResourcesResponse,
    Effect,
    PlanResourcesResponse,
    Principal,
    Resource,
    ResourceDesc,
    ResourceList,
)
from cerbos.sdk.shadow.engine import InMemoryCerbosEngine, evaluate_plan_filter
from cerbos.sdk.shadow.model import (
    ShadowAuditEntry,
    ShadowCheckReport,
    ShadowOutcome,
    ShadowPlanReport,
    ShadowPlanResourceReport,
)


def _new_request_id(request_id: str | None) -> str:
    return request_id if request_id is not None else str(uuid.uuid4())


def _classify(approved, candidate) -> ShadowOutcome:
    if candidate is None:
        return ShadowOutcome.INCONCLUSIVE
    if approved == candidate:
        return ShadowOutcome.MATCH
    return ShadowOutcome.DIFFER


_WORST_ORDER = {
    ShadowOutcome.MATCH: 0,
    ShadowOutcome.INCONCLUSIVE: 1,
    ShadowOutcome.DIFFER: 2,
}


class AsyncShadowCerbosClient:
    """Compare approved and candidate policies while enforcing the approved one.

    Args:
        approved_engine: in-memory engine holding the approved policy version.
            Every business decision comes from this engine.
        candidate_engine: in-memory engine holding the candidate policy version.
            Used only for the shadow comparison.
        shadow_timeout_secs: maximum time to wait for the candidate. Candidate
            calls exceeding this are recorded as inconclusive.
        logger: logger for candidate-side errors.
    """

    def __init__(
        self,
        approved_engine: InMemoryCerbosEngine,
        candidate_engine: InMemoryCerbosEngine,
        *,
        shadow_timeout_secs: float = 1.0,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        self._approved = approved_engine
        self._candidate = candidate_engine
        self._shadow_timeout = shadow_timeout_secs
        self._logger = logger
        self.audit_log: list[ShadowAuditEntry] = []

    @property
    def approved_engine(self) -> InMemoryCerbosEngine:
        return self._approved

    @property
    def candidate_engine(self) -> InMemoryCerbosEngine:
        return self._candidate

    async def _run_candidate(self, fn, *args):
        """Run a candidate decision, converting any failure into ``(None, err)``.

        The blocking work runs on a daemon worker thread so it never occupies the
        event loop.  ``anyio.to_thread.run_sync`` cannot be cancelled while the
        underlying function is still running, so completion is signalled through
        a plain :class:`threading.Event` and awaited under a deadline; a deadline
        breach therefore surfaces promptly even though the worker keeps running.
        """
        done = threading.Event()
        box: dict = {}

        def worker():
            try:
                box["value"] = fn(*args)
            except Exception as exc:  # noqa: BLE001
                # The candidate must never break the approved call.
                box["error"] = exc
            finally:
                done.set()

        threading.Thread(target=worker, daemon=True).start()
        try:
            with anyio.fail_after(self._shadow_timeout):
                while not done.wait(0.01):
                    await anyio.sleep(0)
        except TimeoutError:
            return None, "shadow candidate timed out"

        if "error" in box:
            exc = box["error"]
            self._logger.warning("shadow candidate check failed: %s", exc)
            return None, str(exc)
        return box.get("value"), None

    async def check_resources(
        self,
        principal: Principal,
        resources: ResourceList,
        request_id: str | None = None,
        aux_data=None,
    ) -> CheckResourcesResponse:
        """Return the approved decision and record a shadow comparison."""
        req_id = _new_request_id(request_id)
        resource_actions = list(resources.resources)

        approved_response = await anyio.to_thread.run_sync(
            self._approved.check_resources, principal, resource_actions, req_id
        )
        candidate_response, error = await self._run_candidate(
            self._candidate.check_resources, principal, resource_actions, req_id
        )

        reports: list[ShadowCheckReport] = []
        for approved_result in approved_response.results or []:
            for action, approved_effect in approved_result.actions.items():
                candidate_effect = _effect_from(
                    candidate_response, approved_result.resource.id, action
                )
                outcome = _classify(approved_effect, candidate_effect)
                reports.append(
                    ShadowCheckReport(
                        resource_id=approved_result.resource.id,
                        action=action,
                        approved_effect=approved_effect,
                        candidate_effect=candidate_effect,
                        outcome=outcome,
                        error=error if outcome == ShadowOutcome.INCONCLUSIVE else None,
                    )
                )

        entry = ShadowAuditEntry(
            operation="check_resources",
            request_id=req_id,
            outcome=_worst(report.outcome for report in reports),
            check_reports=reports,
            error=error,
        )
        self.audit_log.append(entry)
        approved_response.shadow_report = entry  # type: ignore[attr-defined]
        return approved_response

    async def is_allowed(
        self,
        action: str,
        principal: Principal,
        resource: Resource,
        request_id: str | None = None,
        aux_data=None,
    ) -> bool:
        """Return the approved allow/deny for a single action."""
        response = await self.check_resources(
            principal=principal,
            resources=ResourceList().add(resource, {action}),
            request_id=request_id,
            aux_data=aux_data,
        )
        result = response.get_resource(resource.id)
        return result is not None and result.is_allowed(action)

    async def plan_resources(
        self,
        actions: str | list[str],
        principal: Principal,
        resource: ResourceDesc,
        request_id: str | None = None,
        aux_data=None,
        *,
        evaluation_resources: Sequence[Resource] | None = None,
    ) -> PlanResourcesResponse:
        """Return the approved plan and compare the two plans per resource.

        Args:
            evaluation_resources: concrete resources used to evaluate both plan
                filters.  Plans whose filter references a missing attribute are
                undefined for that resource (``None`` decision), which is
                recorded as inconclusive rather than treated as a difference.
        """
        req_id = _new_request_id(request_id)
        action_list = [actions] if isinstance(actions, str) else list(actions)

        approved_plan = await anyio.to_thread.run_sync(
            self._approved.plan_resources,
            action_list,
            principal,
            resource,
            req_id,
        )
        candidate_plan, error = await self._run_candidate(
            self._candidate.plan_resources,
            action_list,
            principal,
            resource,
            req_id,
        )

        resource_reports: list[ShadowPlanResourceReport] = []
        for eval_resource in evaluation_resources or []:
            approved_decision = evaluate_plan_filter(
                approved_plan, principal, eval_resource
            )
            candidate_decision = (
                None
                if candidate_plan is None
                else evaluate_plan_filter(candidate_plan, principal, eval_resource)
            )
            resource_reports.append(
                ShadowPlanResourceReport(
                    resource_id=eval_resource.id,
                    approved_decision=approved_decision,
                    candidate_decision=candidate_decision,
                    outcome=_classify(approved_decision, candidate_decision),
                    error=error if candidate_plan is None else None,
                )
            )

        if candidate_plan is None:
            overall = ShadowOutcome.INCONCLUSIVE
        else:
            overall = _worst(
                (report.outcome for report in resource_reports),
                default=ShadowOutcome.MATCH,
            )

        plan_report = ShadowPlanReport(
            action=approved_plan.action,
            resource_kind=approved_plan.resource_kind,
            approved_plan=approved_plan,
            candidate_plan=candidate_plan,
            resource_reports=resource_reports,
            outcome=overall,
            error=error,
        )
        entry = ShadowAuditEntry(
            operation="plan_resources",
            request_id=req_id,
            outcome=overall,
            plan_report=plan_report,
            error=error,
        )
        self.audit_log.append(entry)
        approved_plan.shadow_report = entry  # type: ignore[attr-defined]
        return approved_plan


def _effect_from(
    response: CheckResourcesResponse | None, resource_id: str, action: str
) -> Effect | None:
    if response is None:
        return None
    result = response.get_resource(resource_id)
    if result is None or action not in result.actions:
        return None
    return result.actions[action]


def _worst(outcomes, default: ShadowOutcome = ShadowOutcome.MATCH) -> ShadowOutcome:
    worst = default
    for outcome in outcomes:
        if _WORST_ORDER[outcome] > _WORST_ORDER[worst]:
            worst = outcome
    return worst
