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

"""Service data-flow approval helpers.

This package provides an opinionated, non-standard analysis layer on top of
CycloneDX service data declarations.
See :mod:`cyclonedx.contrib.dataflow.approval` for details.
"""

__all__ = [
    'DEFAULT_PROTECTION_LEVELS',
    'DOWNGRADE_APPROVAL_PROPERTY',
    'DOWNGRADE_JUSTIFICATION_PROPERTY',
    'PUBLIC_VIEW_RATIONALE',
    'DowngradeApproval',
    'EdgeInspection',
    'EgressInspection',
    'ExcludedFlowRecord',
    'FlowApprovalStatus',
    'FlowRecord',
    'InvalidApprovalEvidence',
    'PublicFlowRecord',
    'PublicFlowView',
    'ServiceFlowApprovalReport',
    'ServiceFlowApprover',
    'ServiceFlowSummary',
    'inspect_service_flows',
    'parse_downgrade_approvals',
]

from .approval import (
    DEFAULT_PROTECTION_LEVELS,
    DOWNGRADE_APPROVAL_PROPERTY,
    DOWNGRADE_JUSTIFICATION_PROPERTY,
    PUBLIC_VIEW_RATIONALE,
    DowngradeApproval,
    EdgeInspection,
    EgressInspection,
    ExcludedFlowRecord,
    FlowApprovalStatus,
    FlowRecord,
    InvalidApprovalEvidence,
    PublicFlowRecord,
    PublicFlowView,
    ServiceFlowApprovalReport,
    ServiceFlowApprover,
    ServiceFlowSummary,
    inspect_service_flows,
    parse_downgrade_approvals,
)
