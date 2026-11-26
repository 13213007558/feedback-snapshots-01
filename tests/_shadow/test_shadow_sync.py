# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

from cerbos.sdk.model import Effect, ResourceList
from cerbos.sdk.shadow import ShadowCerbosClient, ShadowOutcome
from cerbos.sdk.shadow.model import (
    ShadowCheckReport,
    ShadowPlanResourceReport,
)


def _report_by_id(reports, resource_id):
    return next(report for report in reports if report.resource_id == resource_id)


def _make_client(approved_engine, candidate_engine, timeout=1.0):
    return ShadowCerbosClient(
        approved_engine, candidate_engine, shadow_timeout_secs=timeout
    )


class TestShadowCheckResources:
    def test_business_always_uses_approved_decision(
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

        response = client.check_resources(principal, resource_list)

        # The returned response is exactly the approved engine's response.
        expected = approved_engine.check_resources(
            principal, list(resource_list.resources), response.request_id
        )
        assert [r.actions for r in response.results] == [
            r.actions for r in expected.results
        ]
        # The diverging resource is denied by the approved policy even though the
        # candidate would allow it - the business enforces the approved result.
        missing_owner_result = response.get_resource(missing_owner_resource.id)
        assert missing_owner_result.is_allowed(action) is False
        assert (
            missing_owner_result.actions[action] == Effect.DENY
        )

    def test_is_allowed_returns_approved_boolean(
        self,
        approved_engine,
        candidate_engine,
        principal,
        action,
        complete_resource,
        missing_owner_resource,
    ):
        client = _make_client(approved_engine, candidate_engine)
        assert client.is_allowed(action, principal, complete_resource) is True
        # Candidate allows this one, but the approved policy denies it.
        assert client.is_allowed(action, principal, missing_owner_resource) is False

    def test_audit_distinguishes_match_differ_and_inconclusive(
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

        response = client.check_resources(principal, resource_list)
        entry = response.shadow_report
        reports = entry.check_reports

        assert all(isinstance(report, ShadowCheckReport) for report in reports)
        complete = _report_by_id(reports, complete_resource.id)
        missing_owner = _report_by_id(reports, missing_owner_resource.id)
        missing_all = _report_by_id(reports, missing_all_resource.id)

        # Same decision on the fully attributed resource.
        assert complete.outcome == ShadowOutcome.MATCH
        assert complete.approved_effect == Effect.ALLOW
        assert complete.candidate_effect == Effect.ALLOW
        assert complete.error is None

        # Confirmed difference where the attribute is missing.
        assert missing_owner.outcome == ShadowOutcome.DIFFER
        assert missing_owner.approved_effect == Effect.DENY
        assert missing_owner.candidate_effect == Effect.ALLOW
        assert missing_owner.error is None

        # Both deny when no attributes exist - still a confirmed match.
        assert missing_all.outcome == ShadowOutcome.MATCH
        assert missing_all.approved_effect == Effect.DENY
        assert missing_all.candidate_effect == Effect.DENY

        # Worst outcome across the batch is the confirmed difference.
        assert entry.outcome == ShadowOutcome.DIFFER

    def test_evidence_records_both_sources(
        self,
        approved_engine,
        candidate_engine,
        principal,
        action,
        missing_owner_resource,
    ):
        client = _make_client(approved_engine, candidate_engine)
        response = client.check_resources(
            principal, ResourceList().add(missing_owner_resource, {action})
        )
        report = response.shadow_report.check_reports[0]
        assert report.source == {
            "approved": Effect.DENY,
            "candidate": Effect.ALLOW,
        }
        assert client.audit_log[-1].request_id == response.request_id


class TestShadowPlanResources:
    def test_plans_with_different_expression_order_agree_on_complete_resource(
        self,
        approved_engine,
        candidate_engine,
        principal,
        action,
        resource_desc,
        complete_resource,
    ):
        client = _make_client(approved_engine, candidate_engine)
        response = client.plan_resources(
            action,
            principal,
            resource_desc,
            evaluation_resources=[complete_resource],
        )

        plan_report = response.shadow_report.plan_report
        # Both sources are retained even though the filter trees differ in order.
        assert plan_report.approved_plan is response
        assert plan_report.candidate_plan is not None
        assert plan_report.filter_kinds["approved"] is not None
        assert plan_report.filter_kinds["candidate"] is not None

        report = plan_report.resource_reports[0]
        assert report.resource_id == complete_resource.id
        assert report.approved_decision is True
        assert report.candidate_decision is True
        assert report.outcome == ShadowOutcome.MATCH

    def test_plan_difference_on_resource_missing_attribute(
        self,
        approved_engine,
        candidate_engine,
        principal,
        action,
        resource_desc,
        missing_owner_resource,
    ):
        client = _make_client(approved_engine, candidate_engine)
        response = client.plan_resources(
            action,
            principal,
            resource_desc,
            evaluation_resources=[missing_owner_resource],
        )
        report = response.shadow_report.plan_report.resource_reports[0]
        assert isinstance(report, ShadowPlanResourceReport)
        # Approved filter resolves to a concrete deny, candidate to a concrete allow.
        assert report.approved_decision is False
        assert report.candidate_decision is True
        assert report.outcome == ShadowOutcome.DIFFER
        assert report.source == {"approved": False, "candidate": True}

    def test_plan_inconclusive_when_candidate_undefined(
        self,
        approved_engine,
        candidate_engine,
        principal,
        action,
        resource_desc,
        missing_all_resource,
    ):
        client = _make_client(approved_engine, candidate_engine)
        response = client.plan_resources(
            action,
            principal,
            resource_desc,
            evaluation_resources=[missing_all_resource],
        )
        report = response.shadow_report.plan_report.resource_reports[0]
        # The approved plan still yields a concrete (deny) decision.
        assert report.approved_decision is False
        # The candidate filter references a missing attribute -> no conclusion.
        assert report.candidate_decision is None
        assert report.outcome == ShadowOutcome.INCONCLUSIVE
        assert response.shadow_report.outcome == ShadowOutcome.INCONCLUSIVE

    def test_plan_report_rolls_up_all_three_outcomes(
        self,
        approved_engine,
        candidate_engine,
        principal,
        action,
        resource_desc,
        evaluation_resources,
    ):
        client = _make_client(approved_engine, candidate_engine)
        response = client.plan_resources(
            action,
            principal,
            resource_desc,
            evaluation_resources=evaluation_resources,
        )
        plan_report = response.shadow_report.plan_report
        outcomes = {
            report.resource_id: report.outcome
            for report in plan_report.resource_reports
        }
        assert outcomes["doc-complete"] == ShadowOutcome.MATCH
        assert outcomes["doc-missing-owner"] == ShadowOutcome.DIFFER
        assert outcomes["doc-missing-all"] == ShadowOutcome.INCONCLUSIVE
        assert plan_report.outcome == ShadowOutcome.DIFFER


class TestShadowResilience:
    def test_late_candidate_does_not_block_or_fail_check(
        self,
        approved_engine,
        slow_candidate_engine,
        principal,
        action,
        complete_resource,
    ):
        client = _make_client(approved_engine, slow_candidate_engine, timeout=0.1)
        response = client.check_resources(
            principal, ResourceList().add(complete_resource, {action})
        )

        # The business response is still the approved allow.
        assert response.get_resource(complete_resource.id).is_allowed(action) is True
        entry = response.shadow_report
        assert entry.outcome == ShadowOutcome.INCONCLUSIVE
        assert entry.error == "shadow candidate timed out"
        report = entry.check_reports[0]
        assert report.candidate_effect is None
        assert report.approved_effect == Effect.ALLOW

    def test_late_candidate_does_not_block_or_fail_plan(
        self,
        approved_engine,
        slow_candidate_engine,
        principal,
        action,
        resource_desc,
        complete_resource,
    ):
        client = _make_client(approved_engine, slow_candidate_engine, timeout=0.1)
        response = client.plan_resources(
            action,
            principal,
            resource_desc,
            evaluation_resources=[complete_resource],
        )
        entry = response.shadow_report
        assert entry.outcome == ShadowOutcome.INCONCLUSIVE
        assert entry.plan_report.candidate_plan is None
        assert entry.plan_report.error == "shadow candidate timed out"
        # Approved plan still resolves.
        assert entry.plan_report.resource_reports[0].approved_decision is True

    def test_failed_candidate_is_recorded_as_inconclusive(
        self,
        approved_engine,
        candidate_engine,
        principal,
        action,
        complete_resource,
    ):
        candidate_engine.failure = RuntimeError("candidate PDP down")
        client = _make_client(approved_engine, candidate_engine)
        response = client.check_resources(
            principal, ResourceList().add(complete_resource, {action})
        )
        entry = response.shadow_report
        assert entry.outcome == ShadowOutcome.INCONCLUSIVE
        assert "candidate PDP down" in entry.error
        # Business decision remains available and correct.
        assert response.get_resource(complete_resource.id).is_allowed(action) is True

    def test_audit_log_collects_every_operation(
        self,
        approved_engine,
        candidate_engine,
        principal,
        action,
        resource_desc,
        complete_resource,
    ):
        client = _make_client(approved_engine, candidate_engine)
        client.check_resources(
            principal, ResourceList().add(complete_resource, {action})
        )
        client.plan_resources(
            action, principal, resource_desc, evaluation_resources=[complete_resource]
        )
        operations = [entry.operation for entry in client.audit_log]
        assert operations == ["check_resources", "plan_resources"]
        assert all(entry.request_id for entry in client.audit_log)


class TestShadowEdgeCases:
    def test_empty_resource_batch_is_match_without_error(
        self, approved_engine, candidate_engine, principal
    ):
        client = _make_client(approved_engine, candidate_engine)
        response = client.check_resources(principal, ResourceList())
        assert response.results == []
        assert response.shadow_report.outcome == ShadowOutcome.MATCH
        assert response.shadow_report.check_reports == []

    def test_plan_without_evaluation_resources_compares_filter_kinds(
        self,
        approved_engine,
        candidate_engine,
        principal,
        action,
        resource_desc,
    ):
        client = _make_client(approved_engine, candidate_engine)
        response = client.plan_resources(action, principal, resource_desc)
        plan_report = response.shadow_report.plan_report
        assert plan_report.approved_plan is response
        assert plan_report.candidate_plan is not None
        assert plan_report.resource_reports == []
        assert response.shadow_report.outcome == ShadowOutcome.MATCH
