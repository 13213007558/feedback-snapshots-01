# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

from io import StringIO
from json import loads as json_loads
from unittest import TestCase

from cyclonedx.contrib.dataflow import (
    DOWNGRADE_APPROVAL_PROPERTY,
    DOWNGRADE_JUSTIFICATION_PROPERTY,
    PUBLIC_VIEW_RATIONALE,
    FlowApprovalStatus,
    InvalidApprovalEvidence,
    ServiceFlowApprover,
    inspect_service_flows,
    parse_downgrade_approvals,
)
from cyclonedx.model import DataClassification, DataFlow, Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.service import Service
from cyclonedx.output.json import JsonV1Dot7
from cyclonedx.output.xml import XmlV1Dot7
from tests._data.models import get_bom_with_service_dataflow_cycle


def _assertion_data() -> Service:
    return Service(
        name='analytics', bom_ref='svc-analytics',
        data=[
            DataClassification(flow=DataFlow.INBOUND, classification='restricted'),
            DataClassification(flow=DataFlow.OUTBOUND, classification='public'),
        ],
        properties=[
            Property(name=DOWNGRADE_APPROVAL_PROPERTY, value='public;approval-id=APR-1;method=hashing'),
        ],
    )


def _ingest_service() -> Service:
    return Service(
        name='status-page', bom_ref='svc-status-page',
        data=[DataClassification(flow=DataFlow.INBOUND, classification='public')],
    )


def _two_service_bom(source: Service, target: Service) -> Bom:
    return Bom(
        services=[source, target],
        dependencies=[Dependency(source.bom_ref, [Dependency(target.bom_ref)])],
    )


class TestServiceFlowApprover(TestCase):

    def test_dependency_cycle_is_visible(self) -> None:
        approver = ServiceFlowApprover(get_bom_with_service_dataflow_cycle())
        self.assertIn(('svc-orders', 'svc-analytics'), approver.edge_candidates)
        self.assertIn(('svc-analytics', 'svc-orders'), approver.edge_candidates)

    def test_approved_downgrade_egress(self) -> None:
        report = inspect_service_flows(get_bom_with_service_dataflow_cycle())
        analytics = report.service('svc-analytics')
        self.assertIsNotNone(analytics)
        public_egress = next(
            egress for egress in analytics.approved_egresses  # type: ignore[union-attr]
            if egress.flow.normalized_classification == 'public'
        )
        self.assertTrue(public_egress.can_be_sent)
        self.assertIn('approved-downgrade', public_egress.reasons)
        self.assertIsNotNone(public_egress.approval)
        self.assertEqual('APR-2026-014', public_egress.approval.approval_id)  # type: ignore[union-attr]
        self.assertEqual(('svc-status-page',), public_egress.destinations)

    def test_restricted_egress_is_above_public_ceiling(self) -> None:
        report = inspect_service_flows(get_bom_with_service_dataflow_cycle())
        analytics = report.service('svc-analytics')
        restricted_egress = next(
            egress for egress in analytics.egresses  # type: ignore[union-attr]
            if egress.flow.direction is DataFlow.OUTBOUND
            and egress.flow.normalized_classification == 'restricted'
        )
        self.assertTrue(restricted_egress.can_be_sent)
        self.assertTrue(any(
            line.startswith('outbound restricted:') and 'above-public-ceiling' in line
            for line in report.explain_public_view_exclusion('svc-analytics', 'restricted')
        ))

    def test_dependency_without_flow_declaration_is_left_for_review(self) -> None:
        report = inspect_service_flows(get_bom_with_service_dataflow_cycle())
        edge = next(
            edge for edge in report.edges
            if (edge.source_ref, edge.target_ref) == ('svc-orders', 'svc-notifications')
        )
        self.assertIs(FlowApprovalStatus.REVIEW, edge.status)
        self.assertTrue(edge.needs_review)
        self.assertIn('missing-flow-declaration:target', edge.reasons)
        self.assertIsNone(edge.egress_can_be_sent)
        self.assertIn(edge, report.review_edges)

    def test_classification_mismatch_is_left_for_review(self) -> None:
        source = Service(
            name='sender', bom_ref='svc-sender',
            data=[
                DataClassification(flow=DataFlow.INBOUND, classification='internal'),
                DataClassification(flow=DataFlow.OUTBOUND, classification='internal'),
            ],
        )
        target = Service(
            name='receiver', bom_ref='svc-receiver',
            data=[DataClassification(flow=DataFlow.INBOUND, classification='public')],
        )
        report = inspect_service_flows(_two_service_bom(source, target))
        self.assertIs(FlowApprovalStatus.REVIEW, report.edges[0].status)
        self.assertIn('no-matching-flow-declaration', report.edges[0].reasons)

    def test_unknown_protection_level_is_not_sent(self) -> None:
        report = inspect_service_flows(get_bom_with_service_dataflow_cycle())
        edge = next(
            edge for edge in report.edges
            if (edge.source_ref, edge.target_ref) == ('svc-partner-feed', 'svc-status-page')
        )
        self.assertIs(FlowApprovalStatus.UNKNOWN, edge.status)
        self.assertTrue(edge.egress_is_unknown)
        self.assertIsNone(edge.egress_can_be_sent)

    def test_direction_mismatch_is_rejected(self) -> None:
        source = Service(
            name='receiver-only', bom_ref='svc-receiver',
            data=[DataClassification(flow=DataFlow.INBOUND, classification='public')],
        )
        bom = _two_service_bom(source, _ingest_service())
        report = inspect_service_flows(bom)
        self.assertIs(FlowApprovalStatus.REJECTED, report.edges[0].status)
        self.assertIn('direction-mismatch:source', report.edges[0].reasons)
        self.assertIs(False, report.edges[0].egress_can_be_sent)

    def test_downgrade_without_approval_is_rejected(self) -> None:
        source = Service(
            name='analytics', bom_ref='svc-analytics',
            data=[
                DataClassification(flow=DataFlow.INBOUND, classification='restricted'),
                DataClassification(flow=DataFlow.OUTBOUND, classification='public'),
            ],
        )
        report = inspect_service_flows(_two_service_bom(source, _ingest_service()))
        self.assertIs(FlowApprovalStatus.REJECTED, report.edges[0].status)
        self.assertIn('downgrade-without-approval', report.edges[0].reasons)

    def test_downgrade_without_justification_is_rejected(self) -> None:
        source = _assertion_data()
        source.properties = [Property(name=DOWNGRADE_APPROVAL_PROPERTY, value='public;approval-id=APR-1')]
        report = inspect_service_flows(_two_service_bom(source, _ingest_service()))
        self.assertIs(FlowApprovalStatus.REJECTED, report.edges[0].status)
        self.assertIn('downgrade-without-justification', report.edges[0].reasons)

    def test_invalid_approval_evidence_is_rejected(self) -> None:
        source = _assertion_data()
        source.properties.add(Property(name=DOWNGRADE_APPROVAL_PROPERTY, value='public;oops'))
        with self.assertRaises(InvalidApprovalEvidence):
            parse_downgrade_approvals(source)
        report = inspect_service_flows(_two_service_bom(source, _ingest_service()))
        self.assertIs(FlowApprovalStatus.REJECTED, report.edges[0].status)
        self.assertIn('invalid-approval-evidence', report.edges[0].reasons)

    def test_justification_property_is_used_as_evidence(self) -> None:
        source = _assertion_data()
        source.properties.add(Property(
            name=DOWNGRADE_JUSTIFICATION_PROPERTY,
            value='Identifiers replaced by salted hashes'))
        approvals = parse_downgrade_approvals(source)
        self.assertEqual('Identifiers replaced by salted hashes', approvals[0].justification)
        report = inspect_service_flows(_two_service_bom(source, _ingest_service()))
        self.assertIs(FlowApprovalStatus.APPROVED, report.edges[0].status)
        self.assertIn('approved-downgrade', report.edges[0].reasons)

    def test_unknown_inbound_baseline_blocks_downgrade_decision(self) -> None:
        source = Service(
            name='analytics', bom_ref='svc-analytics',
            data=[
                DataClassification(flow=DataFlow.INBOUND, classification='restricted'),
                DataClassification(flow=DataFlow.INBOUND, classification='mystery-tier'),
                DataClassification(flow=DataFlow.OUTBOUND, classification='public'),
            ],
            properties=[
                Property(name=DOWNGRADE_APPROVAL_PROPERTY, value='public;approval-id=APR-1'),
                Property(name=DOWNGRADE_JUSTIFICATION_PROPERTY, value='Redacted'),
            ],
        )
        report = inspect_service_flows(_two_service_bom(source, _ingest_service()))
        self.assertIs(FlowApprovalStatus.UNKNOWN, report.edges[0].status)
        self.assertIn('inbound-baseline-unknown', report.edges[0].reasons)

    def test_nested_services_are_analyzed(self) -> None:
        child = Service(
            name='child', bom_ref='svc-child',
            data=[
                DataClassification(flow=DataFlow.INBOUND, classification='public'),
                DataClassification(flow=DataFlow.OUTBOUND, classification='public'),
            ],
        )
        parent = Service(name='parent', bom_ref='svc-parent', services=[child])
        target = _ingest_service()
        bom = Bom(services=[parent, target], dependencies=[
            Dependency(child.bom_ref, [Dependency(target.bom_ref)]),
        ])
        report = inspect_service_flows(bom)
        self.assertIsNotNone(report.service('svc-child'))
        self.assertIs(FlowApprovalStatus.APPROVED, report.edges[0].status)

    def test_unknown_direction_is_kept_unknown(self) -> None:
        source = Service(
            name='legacy', bom_ref='svc-legacy',
            data=[DataClassification(flow=DataFlow.UNKNOWN, classification='public')],
        )
        report = inspect_service_flows(_two_service_bom(source, _ingest_service()))
        self.assertIs(FlowApprovalStatus.UNKNOWN, report.edges[0].status)
        self.assertIn('unknown-flow-direction', report.edges[0].reasons)
        self.assertEqual((), report.public_view.records)


class TestPublicFlowView(TestCase):

    def test_public_view_only_contains_approved_public_egress(self) -> None:
        report = inspect_service_flows(get_bom_with_service_dataflow_cycle())
        classifications = {(record.service_ref, record.classification)
                           for record in report.public_view.records}
        self.assertIn(('svc-analytics', 'public'), classifications)
        self.assertNotIn(('svc-analytics', 'restricted'), classifications)
        self.assertNotIn(('svc-status-page', 'public'), classifications)
        public_record = report.public_view.records[0]
        self.assertEqual(('svc-status-page',), public_record.destinations)
        self.assertEqual('APR-2026-014', public_record.approval_id)

    def test_restricted_ingress_is_explained(self) -> None:
        report = inspect_service_flows(get_bom_with_service_dataflow_cycle())
        explanation = report.explain_public_view_exclusion('svc-analytics', 'restricted')
        self.assertTrue(any('inbound restricted' in line for line in explanation))
        self.assertIn(PUBLIC_VIEW_RATIONALE[1], explanation)
        self.assertIn(PUBLIC_VIEW_RATIONALE[2], explanation)

    def test_public_egress_does_not_cover_restricted_ingress(self) -> None:
        report = inspect_service_flows(get_bom_with_service_dataflow_cycle())
        analytics = report.service('svc-analytics')
        self.assertIsNotNone(analytics)
        self.assertIn('restricted', {flow.classification for flow in analytics.ingress})  # type: ignore[union-attr]
        self.assertNotIn('restricted', {
            record.classification for record in report.public_view.records
            if record.service_ref == 'svc-analytics'
        })


class TestReadBack(TestCase):

    EXPECTED_EDGES: dict[tuple[str, str], tuple[FlowApprovalStatus, object]] = {
        ('svc-analytics', 'svc-orders'): (FlowApprovalStatus.APPROVED, True),
        ('svc-analytics', 'svc-status-page'): (FlowApprovalStatus.APPROVED, True),
        ('svc-orders', 'svc-analytics'): (FlowApprovalStatus.APPROVED, True),
        ('svc-orders', 'svc-notifications'): (FlowApprovalStatus.REVIEW, None),
        ('svc-partner-feed', 'svc-status-page'): (FlowApprovalStatus.UNKNOWN, None),
    }

    def _assert_edges(self, bom: Bom) -> None:
        report = inspect_service_flows(bom)
        self.assertEqual(5, len(report.edges))
        for edge in report.edges:
            expected_status, expected_send = self.EXPECTED_EDGES[(edge.source_ref, edge.target_ref)]
            with self.subTest(edge=f'{edge.source_ref}->{edge.target_ref}'):
                self.assertIs(expected_status, edge.status)
                self.assertIs(expected_send, edge.egress_can_be_sent)

    def test_edges_after_json_read_back(self) -> None:
        bom = get_bom_with_service_dataflow_cycle()
        serialized = JsonV1Dot7(bom).output_as_string()
        self._assert_edges(Bom.from_json(json_loads(serialized)))

    def test_edges_after_xml_read_back(self) -> None:
        bom = get_bom_with_service_dataflow_cycle()
        serialized = XmlV1Dot7(bom).output_as_string()
        self._assert_edges(Bom.from_xml(StringIO(serialized)))

    def test_approval_survives_read_back(self) -> None:
        bom = get_bom_with_service_dataflow_cycle()
        read_back = Bom.from_json(json_loads(JsonV1Dot7(bom).output_as_string()))
        analytics = next(service for service in read_back.services if service.name == 'analytics')
        approvals = parse_downgrade_approvals(analytics)
        self.assertEqual(1, len(approvals))
        self.assertEqual('public', approvals[0].target_classification)
        self.assertEqual('APR-2026-014', approvals[0].approval_id)
        self.assertEqual('pseudonymisation', approvals[0].method)
