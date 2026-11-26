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

"""Build, round-trip, and approve a small cyclic service data-flow graph."""

from json import loads as json_loads

from cyclonedx.contrib.dataflow import FlowApprovalStatus, inspect_service_flows
from cyclonedx.model import DataClassification, DataFlow, Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.service import Service
from cyclonedx.output.json import JsonV1Dot7

orders = Service(
    name='orders', bom_ref='svc-orders',
    data=[
        DataClassification(flow=DataFlow.INBOUND, classification='restricted'),
        DataClassification(flow=DataFlow.OUTBOUND, classification='restricted'),
    ],
)
analytics = Service(
    name='analytics', bom_ref='svc-analytics',
    data=[
        DataClassification(flow=DataFlow.INBOUND, classification='restricted'),
        DataClassification(flow=DataFlow.OUTBOUND, classification='restricted'),
        DataClassification(flow=DataFlow.OUTBOUND, classification='public'),
    ],
    properties=[
        Property(name='cdx:service:dataflow:downgrade-approval',
                 value='public;approval-id=APR-2026-014;method=pseudonymisation'),
        Property(name='cdx:service:dataflow:downgrade-justification',
                 value='Aggregated order metrics with direct identifiers removed'),
    ],
)
status_page = Service(
    name='status-page', bom_ref='svc-status-page',
    data=[DataClassification(flow=DataFlow.INBOUND, classification='public')],
)
notifications = Service(name='notifications', bom_ref='svc-notifications')

bom = Bom(services=[orders, analytics, status_page, notifications], dependencies=[
    Dependency(orders.bom_ref, [Dependency(analytics.bom_ref), Dependency(notifications.bom_ref)]),
    Dependency(analytics.bom_ref, [Dependency(orders.bom_ref), Dependency(status_page.bom_ref)]),
])

# The cycle survives a JSON round-trip, so approval decisions are reproducible
# from a manifest that was read back rather than the in-memory model.
read_back = Bom.from_json(  # type: ignore[attr-defined]
    json_loads(JsonV1Dot7(bom).output_as_string()))

report = inspect_service_flows(read_back)
for edge in report.edges:
    sendable = 'yes' if edge.egress_can_be_sent else 'no' if edge.egress_can_be_sent is False else 'unknown'
    print(f'{edge.source_ref} -> {edge.target_ref}: {edge.status.value} (sendable: {sendable})')
    if edge.status is FlowApprovalStatus.REVIEW:
        print('  left for review:', ', '.join(edge.reasons))

for record in report.public_view.records:
    print(f'public: {record.service_ref} {record.classification} -> {record.destinations}')
print('why restricted ingress is absent:')
for line in report.explain_public_view_exclusion('svc-analytics', 'restricted'):
    print(' ', line)
