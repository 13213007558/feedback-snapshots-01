# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

import anyio
import pytest

from cerbos.sdk.model import Effect, ResourceList
from cerbos.sdk.shadow import AsyncShadowCerbosClient, ShadowOutcome

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _make_client(approved_engine, candidate_engine, timeout=1.0):
    return AsyncShadowCerbosClient(
        approved_engine, candidate_engine, shadow_timeout_secs=timeout
    )


def _report_by_id(reports, resource_id):
    return next(report for report in reports if report.resource_id == resource_id)


class TestAsyncShadowCheckResources:
    async def test_business_uses_approved_decision_and_keeps_three_evidence_states(
        self,
        approved_engine,
        candidate_engine,
        principal,
        action,
        complete_resource,
        missing_owner_resource,
        missing_all_resource,
    ):
        client = _make_client(approved_engine, candidate_engine)
        resource_list = ResourceList()
        for resource in (
            complete_resource,
            missing_owner_resource,
            missing_all_resource,
        ):
            resource_list.add(resource, {action})

        response = await client.check_resources(principal, resource_list)
        reports = response.shadow_report.check_reports

        complete = _report_by_id(reports, complete_resource.id)
        missing_owner = _report_by_id(reports, missing_owner_resource.id)
        missing_all = _report_by_id(reports, missing_all_resource.id)

        assert complete.outcome == ShadowOutcome.MATCH
        assert missing_owner.outcome == ShadowOutcome.DIFFER
        assert missing_owner.approved_effect == Effect.DENY
        assert missing_owner.candidate_effect == Effect.ALLOW
        assert missing_all.outcome == ShadowOutcome.MATCH

        # The enforced decision is the approved deny, not the candidate allow.
        enforced = response.get_resource(missing_owner_resource.id)
        assert enforced.actions[action] == Effect.DENY

    async def test_is_allowed_returns_approved_boolean(
        self,
        approved_engine,
        candidate_engine,
        principal,
        action,
        complete_resource,
        missing_owner_resource,
    ):
        client = _make_client(approved_engine, candidate_engine)
        assert await client.is_allowed(action, principal, complete_resource) is True
        assert (
            await client.is_allowed(action, principal, missing_owner_resource)
            is False
        )


class TestAsyncShadowPlanResources:
    async def test_plan_rolls_up_match_differ_inconclusive(
        self,
        approved_engine,
        candidate_engine,
        principal,
        action,
        resource_desc,
        evaluation_resources,
    ):
        client = _make_client(approved_engine, candidate_engine)
        response = await client.plan_resources(
            action,
            principal,
            resource_desc,
            evaluation_resources=evaluation_resources,
        )
        outcomes = {
            report.resource_id: report.outcome
            for report in response.shadow_report.plan_report.resource_reports
        }
        assert outcomes["doc-complete"] == ShadowOutcome.MATCH
        assert outcomes["doc-missing-owner"] == ShadowOutcome.DIFFER
        assert outcomes["doc-missing-all"] == ShadowOutcome.INCONCLUSIVE
        assert response.shadow_report.outcome == ShadowOutcome.DIFFER


class TestAsyncShadowResilience:
    async def test_late_candidate_is_inconclusive_but_business_responds(
        self,
        approved_engine,
        slow_candidate_engine,
        principal,
        action,
        complete_resource,
        resource_desc,
    ):
        client = _make_client(approved_engine, slow_candidate_engine, timeout=0.1)

        check = await client.check_resources(
            principal, ResourceList().add(complete_resource, {action})
        )
        assert check.shadow_report.outcome == ShadowOutcome.INCONCLUSIVE
        assert check.shadow_report.error == "shadow candidate timed out"
        assert check.get_resource(complete_resource.id).is_allowed(action) is True

        plan = await client.plan_resources(
            action,
            principal,
            resource_desc,
            evaluation_resources=[complete_resource],
        )
        assert plan.shadow_report.outcome == ShadowOutcome.INCONCLUSIVE
        assert plan.shadow_report.plan_report.candidate_plan is None
        resource_reports = plan.shadow_report.plan_report.resource_reports
        assert resource_reports[0].approved_decision is True

    async def test_failed_candidate_does_not_break_business(
        self,
        approved_engine,
        candidate_engine,
        principal,
        action,
        complete_resource,
    ):
        candidate_engine.failure = RuntimeError("candidate PDP down")
        client = _make_client(approved_engine, candidate_engine)
        response = await client.check_resources(
            principal, ResourceList().add(complete_resource, {action})
        )
        assert response.shadow_report.outcome == ShadowOutcome.INCONCLUSIVE
        assert "candidate PDP down" in response.shadow_report.error
        assert response.get_resource(complete_resource.id).is_allowed(action) is True
