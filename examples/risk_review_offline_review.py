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

"""Offline approval-aware risk review scenario.

Run from the repository root:

    .venv/bin/python examples/risk_review_offline_review.py

The script uses only in-memory materials and never accesses the network.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

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


def bom_reference(url: str, comment: str) -> ExternalReference:
    return ExternalReference(type=ExternalReferenceType.BOM, url=XsUri(url), comment=comment)


def approved_external_bom() -> Bom:
    inner = Component(name='approved-inner', bom_ref='approved-inner', version='1.2.3')
    next_level = Component(
        name='next-level',
        bom_ref='next-level',
        external_references=[bom_reference(UNAPPROVED_NEXT_URL, 'next manifest')],
    )
    return Bom(
        components=[inner, next_level],
        dependencies=[Dependency(BomRef('approved-inner'), [Dependency(BomRef('next-level'))])],
        vulnerabilities=[
            Vulnerability(
                id=EXTERNAL_RISK_ID,
                description='Confirmed risk from the approved external BOM',
                affects=[BomTarget(ref='approved-inner')],
            ),
        ],
    )


def root_bom() -> Bom:
    application = Component(name='release-app', bom_ref='release-app', version='4.0.0')
    approved_entry = Component(
        name='approved-entry',
        bom_ref='approved-entry',
        external_references=[
            bom_reference(APPROVED_URL, 'primary approved manifest'),
            bom_reference(APPROVED_URL, 'duplicate pointer to same material'),
        ],
    )
    other_branch = Component(name='other-risk-branch', bom_ref='other-risk')
    return Bom(
        metadata=BomMetaData(component=application),
        components=[approved_entry, other_branch],
        dependencies=[
            Dependency(
                BomRef('release-app'),
                [Dependency(BomRef('approved-entry')), Dependency(BomRef('other-risk'))],
            ),
        ],
        vulnerabilities=[
            Vulnerability(
                id=LOCAL_RISK_ID,
                description='Locally proven risk that must survive an unrelated branch failure',
                affects=[BomTarget(ref='other-risk')],
            ),
        ],
    )


def run_scenario() -> Dict[str, Any]:
    parser = InMemoryMaterialResolver({
        APPROVED_URL: approved_external_bom(),
        # Present in the application parser, but approval must prevent pickup.
        UNAPPROVED_NEXT_URL: Bom(),
    })
    reviewer = RiskReviewer(resolver=parser, approval=ApprovalRegistry([APPROVED_URL]))
    bom = root_bom()

    healthy = reviewer.review(bom)
    healthy_entry = healthy.dependency('approved-entry')
    healthy_other = healthy.dependency('other-risk')
    healthy_checks = {
        'verified_relationships': len(healthy.locally_verified_relationships) == 3,
        'duplicate_pickups': parser.requested_locations == [APPROVED_URL, APPROVED_URL],
        'unapproved_never_picked_up': UNAPPROVED_NEXT_URL not in parser.requested_locations,
        'one_approval_gap': len(healthy.pending_references) == 1,
        'external_risk_retained': healthy_entry is not None
        and EXTERNAL_RISK_ID in [risk.id for risk in healthy_entry.risks],
        'local_risk_confirmed': healthy_other is not None
        and healthy_other.state == RiskState.CONFIRMED_RISK.value,
    }

    parser.fail(APPROVED_URL)
    failed = reviewer.review(bom)
    approved_dependency = failed.dependency('approved-entry')
    other_dependency = failed.dependency('other-risk')
    checks = {
        **healthy_checks,
        'failed_approval_read_keeps_two_positions': len(failed.fetch_log) == 2
        and all(item.status == 'failed' for item in failed.fetch_log),
        'pending_reason_in_original_place': approved_dependency is not None
        and len(approved_dependency.pending_references) == 2
        and all(item.status == ReferenceStatus.READ_FAILED.value
                for item in approved_dependency.external_references),
        'other_branch_result_survives': other_dependency is not None
        and other_dependency.state == RiskState.CONFIRMED_RISK.value
        and [risk.id for risk in other_dependency.risks] == [LOCAL_RISK_ID],
    }

    return {
        'offline': True,
        'all_checks_passed': all(checks.values()),
        'checks': checks,
        'actual_parser_pickup_locations': parser.requested_locations,
        'parser_pickup_log': [record.__dict__ for record in parser.pickup_log],
        'healthy_summary': healthy.summary(),
        'healthy_review': healthy.to_dict(),
        'failed_review': failed.to_dict(),
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Optional path for the JSON scenario report')
    args = parser.parse_args(argv)

    result = run_scenario()
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + '\n', encoding='utf-8')
    print(text)
    return 0 if result['all_checks_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
