.. # Licensed under the Apache License, Version 2.0 (the "License");
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

Service Data-Flow Approval
==========================

:mod:`cyclonedx.contrib.dataflow` is a contrib analysis layer, not part of the
CycloneDX specification. It helps an approval tool decide whether a service may
release data, by cross-checking three things that are recorded separately in a
BOM:

1. **Direction** - ``Service.data`` declares ``inbound``, ``outbound``,
   ``bi-directional`` or ``unknown`` relative to the service.
2. **Service relationship** - a dependency edge from service A to service B is
   the evidence that A calls B. CycloneDX dependencies are a graph, so cycles
   are valid and are preserved on JSON/XML round-trips.
3. **Downgrade evidence** - when an egress is less protected than the service's
   most sensitive ingress, an explicit approval must justify the step.

Why received and sent levels differ
-----------------------------------

The protection level of received material is not the protection level of what
is sent out. An ingress endpoint may de-identify data in an approved way and
then publish a lower classification. The approver compares each outbound
declaration with the service's most sensitive *known* inbound declaration (the
baseline). If the egress is at or above the baseline, no downgrade is involved.
If it is below the baseline, an approval is mandatory.

Downgrade approvals are stored as service properties, so no schema extension is
needed and the evidence survives serialization:

.. code-block:: text

   cdx:service:dataflow:downgrade-approval =
       public;approval-id=APR-2026-014;method=pseudonymisation
   cdx:service:dataflow:downgrade-justification =
       Aggregated order metrics with direct identifiers removed

The approval property starts with the approved target classification. Optional
``key=value`` segments may include ``approval-id``, ``method``, ``reason`` and
``justification``. A ``reason`` segment is used as the justification when no
separate justification property exists.

Statuses
--------

The report uses four statuses:

* ``approved`` - evidence is complete and the egress may be released.
* ``review`` - a dependency exists but there is no declared flow for it: one
  endpoint has no declaration at all, or the declared classifications do not
  overlap across the edge. This is deliberately **not** rejected. A missing
  declaration is an evidence gap, so a human must decide whether one is needed.
* ``rejected`` - the declarations contradict the dependency direction, or a
  downgrade has no approval, a malformed approval, no justification, or an
  approval target that is still more restrictive than the egress.
* ``unknown`` - a declaration exists but cannot be evaluated, for example an
  ``unknown`` direction or a classification outside the protection-level policy.

Reading back and inspecting edge by edge
----------------------------------------

.. code-block:: python

   from json import loads
   from cyclonedx.contrib.dataflow import inspect_service_flows
   from cyclonedx.model.bom import Bom
   from cyclonedx.output.json import JsonV1Dot7

   serialized = JsonV1Dot7(bom).output_as_string()
   report = inspect_service_flows(Bom.from_json(loads(serialized)))

   for edge in report.edges:
       print(edge.source_ref, '->', edge.target_ref, edge.status.value,
             'sendable:', edge.egress_can_be_sent)

``EdgeInspection.egress_can_be_sent`` is ``True`` only for an approved matched
edge, ``False`` for a rejected edge, and ``None`` when evidence is missing or
unknown. This makes the three outcomes distinguishable without inspecting
private state.

``ServiceFlowApprover.edge_candidates`` exposes the service-to-service edges
derived from the dependency graph, including both directions of a cycle.
``ServiceFlowApprover.inspect_egresses`` reports each outbound declaration with
its destinations and approval evidence, independent of which edge is under
review.

The public view
---------------

``PublicFlowView`` is a projection, not a BOM. It contains only outbound
declarations that are approved and at or below the public ceiling. Inbound
declarations are never projected, because they describe data a service
receives, not data it releases.

This is why a restricted ingress can remain absent from the public view even
when the same service has an approved public egress: the approved egress is a
separate declaration with its own evidence, and the ingress is excluded by
direction. ``explain_public_view_exclusion(service_ref, classification)``
returns the concrete reasons for the exclusion plus the general rationale, for
example:

.. code-block:: text

   inbound restricted: above-public-ceiling, inbound-not-egress
   outbound restricted: above-public-ceiling, no-downgrade
   The public view projects only approved outbound flows at or below the public ceiling.
   Inbound-only declarations are never projected: they describe data received, not data released.
   Restricted ingress therefore remains excluded even when the same service has an approved public egress.

Policy configuration
--------------------

The default protection ranking is intentionally small. Pass
``protection_levels`` to :class:`~cyclonedx.contrib.dataflow.ServiceFlowApprover`
to extend or override it, and ``public_ceiling`` to change which rank may be
published. Classifications absent from the effective policy are treated as
unknown rather than guessed.

Known limit: CycloneDX does not bind an individual ``dataflow`` declaration to
a peer. The approver therefore matches declarations by classification across a
dependency edge. When several unrelated classifications share a label, add
distinct classifications so the matches stay unambiguous.

See also the runnable example ``examples/service_dataflow_approval.py`` and the
fixture ``get_bom_with_service_dataflow_cycle`` in ``tests/_data/models.py``.
