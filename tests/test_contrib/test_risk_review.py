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

import json
from unittest import TestCase

from cyclonedx.contrib.risk_review import (
    ApprovalRegistry,
    InMemoryMaterialResolver,
    ReferenceStatus,
    RiskReviewer,
    RiskState,
)
from cyclonedx.model import ExternalReference, ExternalReferenceType, XsUri
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.vulnerability import BomTarget, Vulnerability

APPROVED_URL = 'memory://approved/external-bom.json'
UNAPPROVED_NEXT_URL = 'memory://restricted/next-level-bom.json'
LOCAL_RISK_ID = 'CVE-2026-LOCAL-OTHER-BRANCH'
EXTERNAL_RISK_ID = 'CVE-2026-APPROVED-BRANCH'


def _external_reference(url: str, comment: str) -> ExternalReference:
    return ExternalReference(
        type=ExternalReferenceType.BOM,
        url=XsUri(url),
        comment=comment,
    )


def _approved_bom() -> Bom:
    inner_component = Component(name='approved-inner', bom_ref='approved-inner', version='1.2.3')
    next_component = Component(
        name='next-level',
        bom_ref='next-level',
        version='9.9.9',
        external_references=[_external_reference(UNAPPROVED_NEXT_URL, 'next manifest')],
    )
    return Bom(
        components=[inner_component, next_component],
        dependencies=[
            Dependency(
                BomRef('approved-inner'),
                dependencies=[Dependency(BomRef('next-level'))],
            ),
        ],
        vulnerabilities=[
            Vulnerability(
                id=EXTERNAL_RISK_ID,
                description='confirmed risk read from approved external BOM',
                affects=[BomTarget(ref='approved-inner')],
            ),
        ],
    )


def _root_bom() -> Bom:
    application = Component(name='release-app', bom_ref='release-app', version='4.0.0')
    approved_entry = Component(
        name='approved-entry',
        bom_ref='approved-entry',
        version='2.0.0',
        external_references=[
            _external_reference(APPROVED_URL, 'primary approved manifest'),
            _external_reference(APPROVED_URL, 'duplicate pointer to same material'),
        ],
    )
    other_branch = Component(name='other-risk-branch', bom_ref='other-risk', version='3.0.0')
    return Bom(
        metadata=BomMetaData(component=application),
        components=[approved_entry, other_branch],
        dependencies=[
            Dependency(
                BomRef('release-app'),
                dependencies=[
                    Dependency(BomRef('approved-entry')),
                    Dependency(BomRef('other-risk')),
                ],
            ),
        ],
        vulnerabilities=[
            Vulnerability(
                id=LOCAL_RISK_ID,
                description='locally proven risk on another branch',
                affects=[BomTarget(ref='other-risk')],
            ),
        ],
    )


class RiskReviewScenarioTest(TestCase):
    def setUp(self) -> None:
        self.parser = InMemoryMaterialResolver({
            APPROVED_URL: _approved_bom(),
            # Seed it to prove that missing approval prevents parser pickup.
            UNAPPROVED_NEXT_URL: Bom(),
        })
        self.approval = ApprovalRegistry([APPROVED_URL])
        self.reviewer = RiskReviewer(resolver=self.parser, approval=self.approval)
        self.bom = _root_bom()

    def test_approval_gate_duplicate_pickups_and_three_way_output(self) -> None:
        report = self.reviewer.review(self.bom)

        self.assertEqual(3, len(report.locally_verified_relationships))
        self.assertEqual(
            {('release-app', 'approved-entry'), ('release-app', 'other-risk'),
             ('approved-inner', 'next-level')},
            {(item.ref, item.target_ref) for item in report.locally_verified_relationships},
        )

        root_reviews = [
            item for item in report.reference_reviews
            if item.owner_ref == 'approved-entry' and item.location == APPROVED_URL
        ]
        self.assertEqual(2, len(root_reviews))
        self.assertTrue(all(item.status == ReferenceStatus.VERIFIED.value for item in root_reviews))
        self.assertEqual(1, root_reviews[0].occurrence)
        self.assertEqual(2, root_reviews[1].occurrence)
        self.assertTrue(root_reviews[1].duplicate)
        self.assertEqual(2, len(report.fetch_log))
        self.assertEqual([APPROVED_URL, APPROVED_URL], self.parser.requested_locations)
        self.assertNotIn(UNAPPROVED_NEXT_URL, self.parser.requested_locations)
        self.assertEqual(2, len(report.matched_external_materials))
        self.assertTrue(all(item.matched_by for item in report.matched_external_materials))
        self.assertEqual(
            report.matched_external_materials[0].material_id,
            report.matched_external_materials[1].material_id,
        )

        pending = report.pending_references
        self.assertEqual(1, len(pending))
        missing = pending[0]
        self.assertEqual(UNAPPROVED_NEXT_URL, missing.location)
        self.assertEqual(ReferenceStatus.APPROVAL_MISSING.value, missing.status)
        self.assertFalse(missing.parser_called)
        self.assertEqual('next-level', missing.owner_ref)
        self.assertIn('externalReferences[0]', missing.path)

        approved_dependency = report.dependency('approved-entry')
        other_dependency = report.dependency('other-risk')
        application_dependency = report.dependency('release-app')
        self.assertIsNotNone(approved_dependency)
        self.assertIsNotNone(other_dependency)
        self.assertIsNotNone(application_dependency)
        assert approved_dependency is not None
        assert other_dependency is not None
        assert application_dependency is not None

        self.assertEqual(RiskState.CONFIRMED_RISK_WITH_GAP.value, approved_dependency.state)
        self.assertIn(EXTERNAL_RISK_ID, [risk.id for risk in approved_dependency.risks])
        self.assertTrue(approved_dependency.gap_paths)
        self.assertEqual(RiskState.CONFIRMED_RISK.value, other_dependency.state)
        self.assertIn(LOCAL_RISK_ID, [risk.id for risk in other_dependency.risks])
        self.assertEqual(RiskState.CONFIRMED_RISK_WITH_GAP.value, application_dependency.state)
        self.assertIn(LOCAL_RISK_ID, [risk.id for risk in application_dependency.risks])

        # The complete output is JSON-safe for an approval system.
        json.dumps(report.to_dict())

    def test_approved_material_read_failure_keeps_reason_and_other_branch(self) -> None:
        healthy = self.reviewer.review(self.bom)
        self.assertIn(LOCAL_RISK_ID, [risk.id for risk in healthy.dependency('other-risk').risks])

        self.parser.fail(APPROVED_URL)
        failed = self.reviewer.review(self.bom)

        failed_root_refs = [
            item for item in failed.reference_reviews if item.owner_ref == 'approved-entry'
        ]
        self.assertEqual(2, len(failed_root_refs))
        self.assertTrue(all(item.status == ReferenceStatus.READ_FAILED.value for item in failed_root_refs))
        self.assertTrue(all(item.pending for item in failed_root_refs))
        self.assertTrue(all(item.fetch is not None and item.fetch.error_type == 'OSError'
                            for item in failed_root_refs))
        self.assertEqual(2, len(failed.fetch_log))
        self.assertTrue(all(item.status == 'failed' for item in failed.fetch_log))

        approved_dependency = failed.dependency('approved-entry')
        other_dependency = failed.dependency('other-risk')
        application_dependency = failed.dependency('release-app')
        self.assertIsNotNone(approved_dependency)
        self.assertIsNotNone(other_dependency)
        self.assertIsNotNone(application_dependency)
        assert approved_dependency is not None
        assert other_dependency is not None
        assert application_dependency is not None

        self.assertEqual(2, len(approved_dependency.external_references))
        self.assertEqual(2, len(approved_dependency.pending_references))
        self.assertEqual(RiskState.PENDING_REVIEW.value, approved_dependency.state)
        self.assertEqual([], approved_dependency.risks)

        # The independently proven branch and its propagated fact survive.
        self.assertEqual(RiskState.CONFIRMED_RISK.value, other_dependency.state)
        self.assertEqual([LOCAL_RISK_ID], [risk.id for risk in other_dependency.risks])
        self.assertEqual(RiskState.CONFIRMED_RISK_WITH_GAP.value, application_dependency.state)
        self.assertIn(LOCAL_RISK_ID, [risk.id for risk in application_dependency.risks])
        self.assertTrue(application_dependency.gap_paths)

        encoded = json.loads(failed.to_json())
        self.assertEqual(2, encoded['summary']['pending_references'])
        self.assertEqual(LOCAL_RISK_ID in failed.to_json(), True)

    def test_duplicate_material_across_owners_propagates_gap(self) -> None:
        first = Component(
            name='first-entry', bom_ref='first-entry', external_references=[_external_reference(APPROVED_URL, 'one')]
        )
        second = Component(
            name='second-entry', bom_ref='second-entry', external_references=[_external_reference(APPROVED_URL, 'two')]
        )
        bom = Bom(
            components=[first, second],
            dependencies=[
                Dependency(BomRef('first-entry')),
                Dependency(BomRef('second-entry')),
            ],
        )

        report = self.reviewer.review(bom)

        self.assertEqual(2, self.parser.requested_locations.count(APPROVED_URL))
        for ref in ('first-entry', 'second-entry'):
            dependency = report.dependency(ref)
            self.assertIsNotNone(dependency)
            assert dependency is not None
            self.assertEqual(RiskState.CONFIRMED_RISK_WITH_GAP.value, dependency.state)
            self.assertTrue(dependency.gap_paths)
            self.assertIn(EXTERNAL_RISK_ID, [risk.id for risk in dependency.risks])

    def test_unreadable_unapproved_location_is_not_fetched(self) -> None:
        # Even a resolver configured to fail cannot be reached without approval.
        self.parser.fail(UNAPPROVED_NEXT_URL)
        report = self.reviewer.review(self.bom)
        missing = next(item for item in report.pending_references if item.location == UNAPPROVED_NEXT_URL)
        self.assertEqual(ReferenceStatus.APPROVAL_MISSING.value, missing.status)
        self.assertIsNone(missing.fetch)
        self.assertNotIn(UNAPPROVED_NEXT_URL, self.parser.requested_locations)
