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

"""Approval checks for service data flows declared in a CycloneDX BOM.

The CycloneDX service model declares the *direction* of data relative to a
service, but it does not bind a declaration to a specific peer. This module
combines three sources of evidence that are present in a BOM:

* per-service ``Service.data`` declarations (direction and classification),
* the service-to-service dependency graph (which service calls which), and
* an optional, explicit downgrade approval stored as service properties.

The resulting report is deliberately conservative:

* a dependency between two services that has no matching flow declaration
  is put into :attr:`FlowApprovalStatus.REVIEW` - it is not rejected, because
  the absence of a declaration is an evidence gap, not a policy violation;
* declarations that contradict the dependency direction, or that disclose a
  downgrade without valid approval evidence, are rejected;
* declarations that cannot be evaluated (unknown direction or a
  classification that is not part of the local protection-level policy)
  are reported as :attr:`FlowApprovalStatus.UNKNOWN`.

Downgrade evidence uses CycloneDX properties, so it survives a JSON/XML
round-trip without extending the CycloneDX schema::

    <property name="cdx:service:dataflow:downgrade-approval">
      public;approval-id=APR-2026-014;method=pseudonymisation
    </property>
    <property name="cdx:service:dataflow:downgrade-justification">
      Aggregate order counts with direct identifiers removed
    </property>

The first value segment is the approved target classification. Optional
``key=value`` segments may carry ``approval-id``, ``method``, ``reason`` and
``justification``. A separate justification property may be used instead.
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

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Optional

from ...model import DataFlow
from ...model.bom import Bom
from ...model.dependency import Dependency
from ...model.service import Service

DOWNGRADE_APPROVAL_PROPERTY = 'cdx:service:dataflow:downgrade-approval'
"""Service property that carries an approved target classification."""

DOWNGRADE_JUSTIFICATION_PROPERTY = 'cdx:service:dataflow:downgrade-justification'
"""Service property that carries the rationale for an approved downgrade."""

DEFAULT_PROTECTION_LEVELS: Mapping[str, int] = MappingProxyType({
    # Lower rank means less protected / more publishable.
    'public': 0,
    'internal': 1,
    'sensitive': 2,
    'confidential': 2,
    'restricted': 3,
    'pii': 3,
    'pifi': 3,
    'phi': 3,
    'secret': 4,
})
"""Default ordering of well-known data classifications.

The mapping is intentionally small and opinionated. Applications with their
own taxonomy should pass ``protection_levels`` to :class:`ServiceFlowApprover`.
A classification that is absent from the effective mapping is treated as
unknown and keeps the related flow in review.
"""

PUBLIC_VIEW_RATIONALE: tuple[str, ...] = (
    'The public view projects only approved outbound flows at or below the public ceiling.',
    'Inbound-only declarations are never projected: they describe data received, not data released.',
    'Restricted ingress therefore remains excluded even when the same service has an approved public egress.',
)
"""Human-readable explanation of what the public projection does and does not contain."""


class FlowApprovalStatus(str, Enum):
    """Outcome of an approval check."""

    APPROVED = 'approved'
    """All required evidence is present and the flow may be released."""

    REVIEW = 'review'
    """Evidence is missing; a human must decide whether a flow declaration is needed."""

    REJECTED = 'rejected'
    """Declarations contradict the dependency or a downgrade lacks valid approval."""

    UNKNOWN = 'unknown'
    """A declaration exists, but its direction or protection level cannot be evaluated."""


class InvalidApprovalEvidence(ValueError):
    """Raised when a downgrade-approval property cannot be parsed unambiguously."""


@dataclass(frozen=True)
class DowngradeApproval:
    """Parsed representation of an approved downgrade."""

    target_classification: str
    approval_id: Optional[str] = None
    method: Optional[str] = None
    justification: Optional[str] = None
    raw_value: str = ''


@dataclass(frozen=True)
class FlowRecord:
    """A single ``Service.data`` declaration, normalised for analysis."""

    service_ref: str
    service_name: str
    direction: DataFlow
    classification: str
    protection_level: Optional[int] = None

    @property
    def is_egress(self) -> bool:
        return self.direction in (DataFlow.OUTBOUND, DataFlow.BI_DIRECTIONAL)

    @property
    def is_ingress(self) -> bool:
        return self.direction in (DataFlow.INBOUND, DataFlow.BI_DIRECTIONAL)

    @property
    def is_unknown_direction(self) -> bool:
        return self.direction is DataFlow.UNKNOWN

    @property
    def normalized_classification(self) -> str:
        return self.classification.strip().casefold()


@dataclass(frozen=True)
class EgressInspection:
    """Approval result for one outbound declaration of a service."""

    service_ref: str
    service_name: str
    flow: FlowRecord
    baseline: Optional[FlowRecord]
    approval: Optional[DowngradeApproval] = None
    destinations: tuple[str, ...] = ()
    public_ceiling_rank: Optional[int] = None
    status: FlowApprovalStatus = FlowApprovalStatus.UNKNOWN
    reasons: tuple[str, ...] = ()

    @property
    def can_be_sent(self) -> bool:
        """Whether policy permits releasing this egress at all."""
        return self.status is FlowApprovalStatus.APPROVED

    @property
    def is_unknown(self) -> bool:
        return self.status is FlowApprovalStatus.UNKNOWN

    @property
    def is_public(self) -> bool:
        """Whether this egress is within the configured public ceiling."""
        return (
            self.flow.protection_level is not None
            and self.public_ceiling_rank is not None
            and self.flow.protection_level <= self.public_ceiling_rank
        )


@dataclass(frozen=True)
class EdgeInspection:
    """Approval result for one service-to-service dependency edge."""

    source_ref: str
    source_name: str
    target_ref: str
    target_name: str
    source_egresses: tuple[EgressInspection, ...] = ()
    target_ingress: tuple[FlowRecord, ...] = ()
    matched: bool = False
    crosses_trust_boundary: Optional[bool] = None
    status: FlowApprovalStatus = FlowApprovalStatus.UNKNOWN
    reasons: tuple[str, ...] = ()

    @property
    def egress_can_be_sent(self) -> Optional[bool]:
        """``True``/``False`` when known, ``None`` when evidence is insufficient."""
        if self.matched and self.status is FlowApprovalStatus.APPROVED:
            return True
        if self.status is FlowApprovalStatus.REJECTED:
            return False
        return None

    @property
    def egress_is_unknown(self) -> bool:
        return self.status is FlowApprovalStatus.UNKNOWN

    @property
    def egress_is_public(self) -> bool:
        return any(egress.is_public for egress in self.source_egresses)

    @property
    def needs_review(self) -> bool:
        return self.status is FlowApprovalStatus.REVIEW


@dataclass(frozen=True)
class ServiceFlowSummary:
    """All declarations of one service plus their egress inspections."""

    service_ref: str
    service_name: str
    ingress: tuple[FlowRecord, ...] = ()
    egresses: tuple[EgressInspection, ...] = ()

    @property
    def approved_egresses(self) -> tuple[EgressInspection, ...]:
        return tuple(e for e in self.egresses if e.status is FlowApprovalStatus.APPROVED)

    @property
    def unknown_egresses(self) -> tuple[EgressInspection, ...]:
        return tuple(e for e in self.egresses if e.status is FlowApprovalStatus.UNKNOWN)

    @property
    def rejected_egresses(self) -> tuple[EgressInspection, ...]:
        return tuple(e for e in self.egresses if e.status is FlowApprovalStatus.REJECTED)


@dataclass(frozen=True)
class PublicFlowRecord:
    """An outbound flow that is safe for the public projection."""

    service_ref: str
    service_name: str
    classification: str
    destinations: tuple[str, ...] = ()
    approval_id: Optional[str] = None


@dataclass(frozen=True)
class ExcludedFlowRecord:
    """A flow that is not part of the public projection and why."""

    flow: FlowRecord
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class PublicFlowView:
    """A public projection containing only approved, low-sensitivity egress."""

    ceiling: str
    records: tuple[PublicFlowRecord, ...] = ()
    excluded: tuple[ExcludedFlowRecord, ...] = ()

    @property
    def rationale(self) -> tuple[str, ...]:
        return PUBLIC_VIEW_RATIONALE

    def explain_exclusion(self, service_ref: str,
                          classification: Optional[str] = None) -> tuple[str, ...]:
        """Explain why a service flow is absent from the public projection.

        Returns an empty tuple when no matching exclusion exists. Matching
        exclusion lines are followed by :data:`PUBLIC_VIEW_RATIONALE`.
        """
        wanted = classification.strip().casefold() if classification is not None else None
        lines = tuple(
            f'{excluded.flow.direction.value} {excluded.flow.classification}: '
            f'{", ".join(excluded.reasons)}'
            for excluded in self.excluded
            if excluded.flow.service_ref == service_ref
            and (wanted is None or excluded.flow.normalized_classification == wanted)
        )
        return lines + PUBLIC_VIEW_RATIONALE if lines else ()


@dataclass(frozen=True)
class ServiceFlowApprovalReport:
    """Complete approval report for a BOM's service data flows."""

    services: tuple[ServiceFlowSummary, ...] = ()
    edges: tuple[EdgeInspection, ...] = ()
    public_view: PublicFlowView = field(default_factory=lambda: PublicFlowView(ceiling='public'))

    @property
    def approved_egresses(self) -> tuple[EgressInspection, ...]:
        return tuple(e for s in self.services for e in s.approved_egresses)

    @property
    def unknown_egresses(self) -> tuple[EgressInspection, ...]:
        return tuple(e for s in self.services for e in s.unknown_egresses)

    @property
    def rejected_egresses(self) -> tuple[EgressInspection, ...]:
        return tuple(e for s in self.services for e in s.rejected_egresses)

    @property
    def review_edges(self) -> tuple[EdgeInspection, ...]:
        return tuple(e for e in self.edges if e.status is FlowApprovalStatus.REVIEW)

    @property
    def approved_edges(self) -> tuple[EdgeInspection, ...]:
        return tuple(e for e in self.edges if e.status is FlowApprovalStatus.APPROVED)

    @property
    def unknown_edges(self) -> tuple[EdgeInspection, ...]:
        return tuple(e for e in self.edges if e.status is FlowApprovalStatus.UNKNOWN)

    @property
    def rejected_edges(self) -> tuple[EdgeInspection, ...]:
        return tuple(e for e in self.edges if e.status is FlowApprovalStatus.REJECTED)

    def service(self, service_ref: str) -> Optional[ServiceFlowSummary]:
        return next((s for s in self.services if s.service_ref == service_ref), None)

    def explain_public_view_exclusion(self, service_ref: str,
                                      classification: Optional[str] = None) -> tuple[str, ...]:
        return self.public_view.explain_exclusion(service_ref, classification)


def parse_downgrade_approvals(service: Service) -> tuple[DowngradeApproval, ...]:
    """Parse all downgrade approvals declared on a service.

    Raises:
        InvalidApprovalEvidence: if any approval property is malformed.
    """
    approvals, errors = _approvals_of(service)
    if errors:
        raise InvalidApprovalEvidence('; '.join(errors))
    return approvals


def _approvals_of(service: Service) -> tuple[tuple[DowngradeApproval, ...], tuple[str, ...]]:
    fallback_justification = next((
        prop.value for prop in service.properties
        if prop.name == DOWNGRADE_JUSTIFICATION_PROPERTY and prop.value
    ), None)
    approvals: list[DowngradeApproval] = []
    errors: list[str] = []
    for prop in service.properties:
        if prop.name != DOWNGRADE_APPROVAL_PROPERTY:
            continue
        try:
            approvals.append(_parse_approval_value(prop.value or '', fallback_justification))
        except InvalidApprovalEvidence as error:
            errors.append(str(error))
    return tuple(approvals), tuple(errors)


def _parse_approval_value(value: str, fallback_justification: Optional[str]) -> DowngradeApproval:
    segments = [segment.strip() for segment in value.split(';') if segment.strip()]
    if not segments:
        raise InvalidApprovalEvidence('downgrade-approval property is empty')

    target_segment, *parameter_segments = segments
    if '=' in target_segment:
        key, _, target_value = target_segment.partition('=')
        if key.strip().casefold() not in ('target', 'classification'):
            raise InvalidApprovalEvidence(
                f'downgrade-approval must start with a target classification, got {target_segment!r}')
        target = target_value.strip()
    else:
        target = target_segment

    if not target:
        raise InvalidApprovalEvidence('downgrade-approval target classification is empty')

    parameters: dict[str, str] = {}
    for segment in parameter_segments:
        key, separator, parameter_value = segment.partition('=')
        if not separator or not key.strip():
            raise InvalidApprovalEvidence(f'malformed downgrade-approval parameter {segment!r}')
        parameters[key.strip().casefold()] = parameter_value.strip()

    return DowngradeApproval(
        target_classification=target,
        approval_id=_first_non_empty(
            parameters.get('approval-id'), parameters.get('approval_id'), parameters.get('id')),
        method=parameters.get('method') or None,
        justification=_first_non_empty(
            parameters.get('justification'), parameters.get('reason'), fallback_justification),
        raw_value=value,
    )


def _first_non_empty(*values: Optional[str]) -> Optional[str]:
    return next((value.strip() for value in values if value and value.strip()), None)


@dataclass(frozen=True)
class _EdgeCandidate:
    source_ref: str
    target_ref: str


class ServiceFlowApprover:
    """Inspect service data flows against dependencies, direction, and approvals.

    Args:
        bom: the BOM to inspect; it may have been read back from JSON or XML.
        protection_levels: additional or overriding classification ranks.
            Lower ranks are less protected. Classifications missing from the
            effective mapping are treated as unknown.
        public_ceiling: classification that is the highest level permitted in
            the public projection. Defaults to ``public``.
    """

    def __init__(self, bom: Bom, *,
                 protection_levels: Optional[Mapping[str, int]] = None,
                 public_ceiling: str = 'public') -> None:
        self._bom = bom
        self._levels = dict(DEFAULT_PROTECTION_LEVELS)
        if protection_levels:
            self._levels.update({key.strip().casefold(): rank for key, rank in protection_levels.items()})
        self._public_ceiling = public_ceiling.strip().casefold()
        ceiling_rank = self._levels.get(self._public_ceiling)
        if ceiling_rank is None:
            raise ValueError(f'public ceiling {public_ceiling!r} is not part of the protection-level policy')
        self._ceiling_rank = ceiling_rank
        self._services = tuple(_iter_services(bom.services))
        self._services_by_ref: dict[str, Service] = {}
        for service in self._services:
            service_ref = str(service.bom_ref)
            if service_ref:
                self._services_by_ref[service_ref] = service
        self._records: dict[str, tuple[FlowRecord, ...]] = {
            service_ref: self._records_for(service)
            for service_ref, service in self._services_by_ref.items()
        }
        # approvals and errors per service, parsed once
        self._approvals: dict[str, tuple[tuple[DowngradeApproval, ...], tuple[str, ...]]] = {
            service_ref: _approvals_of(service)
            for service_ref, service in self._services_by_ref.items()
        }
        self._edge_candidates = self._collect_edges()
        self._destinations: dict[str, dict[str, tuple[str, ...]]] = {
            service_ref: self._destinations_for(service_ref)
            for service_ref in self._services_by_ref
        }

    def _records_for(self, service: Service) -> tuple[FlowRecord, ...]:
        service_ref = str(service.bom_ref)
        return tuple(
            FlowRecord(
                service_ref=service_ref,
                service_name=service.name,
                direction=declaration.flow,
                classification=declaration.classification,
                protection_level=self._rank(declaration.classification),
            )
            for declaration in sorted(
                service.data, key=lambda d: (d.flow.value, d.classification.casefold()))
        )

    def _rank(self, classification: str) -> Optional[int]:
        return self._levels.get(classification.strip().casefold())

    def _records_of(self, service_ref: str) -> tuple[FlowRecord, ...]:
        return self._records.get(service_ref, ())

    def _destinations_for(self, service_ref: str) -> dict[str, tuple[str, ...]]:
        destinations: dict[str, list[str]] = {}
        for edge in self._edge_candidates:
            if edge.source_ref != service_ref:
                continue
            source_records = self._records_of(edge.source_ref)
            target_labels = {
                record.normalized_classification
                for record in self._records_of(edge.target_ref)
                if record.is_ingress
            }
            for record in source_records:
                if record.is_egress and record.normalized_classification in target_labels:
                    destinations.setdefault(record.normalized_classification, []).append(edge.target_ref)
        return {
            classification: tuple(sorted(set(refs)))
            for classification, refs in destinations.items()
        }

    @property
    def edge_candidates(self) -> tuple[tuple[str, str], ...]:
        """Service-to-service edges derived from the dependency graph."""
        return tuple((edge.source_ref, edge.target_ref) for edge in self._edge_candidates)

    def _egress_candidates(self, service_ref: str) -> tuple[EgressInspection, ...]:
        records = self._records_of(service_ref)
        ingress = tuple(record for record in records if record.is_ingress)
        approvals, approval_errors = self._approvals[service_ref]
        destinations = self._destinations.get(service_ref, {})
        return tuple(
            self._inspect_egress(record, ingress, approvals, approval_errors,
                                 destinations.get(record.normalized_classification, ()))
            for record in records
            if record.is_egress
        )

    def _inspect_egress(self, record: FlowRecord, ingress: tuple[FlowRecord, ...],
                        approvals: tuple[DowngradeApproval, ...], approval_errors: tuple[str, ...],
                        destinations: tuple[str, ...]) -> EgressInspection:
        known_ingress = tuple(item for item in ingress if item.protection_level is not None)
        baseline = max(
            known_ingress,
            key=lambda item: item.protection_level,  # type: ignore[arg-type,return-value]
            default=None,
        )
        unknown_ingress = any(item.protection_level is None for item in ingress)

        def result(status: FlowApprovalStatus, *reasons: str,
                   approval: Optional[DowngradeApproval] = None) -> EgressInspection:
            extra = ('unknown-protection-level',) if record.protection_level is None else ()
            return EgressInspection(
                service_ref=record.service_ref,
                service_name=record.service_name,
                flow=record,
                baseline=baseline,
                approval=approval,
                destinations=destinations,
                public_ceiling_rank=self._ceiling_rank,
                status=status,
                reasons=tuple(sorted({*reasons, *extra})),
            )

        record_level = record.protection_level
        if record_level is None:
            return result(FlowApprovalStatus.UNKNOWN, 'unknown-protection-level')

        if baseline is None or baseline.protection_level is None:
            return result(FlowApprovalStatus.UNKNOWN, 'no-inbound-baseline')

        if unknown_ingress:
            # The true baseline may be higher than any level we understand,
            # so a judgment that this egress is not a downgrade is unsafe.
            return result(FlowApprovalStatus.UNKNOWN, 'inbound-baseline-unknown',
                          approval=approvals[0] if len(approvals) == 1 else None)

        if record_level >= baseline.protection_level:
            return result(FlowApprovalStatus.APPROVED, 'no-downgrade')

        if approval_errors:
            return result(FlowApprovalStatus.REJECTED, 'invalid-approval-evidence')

        if not approvals:
            return result(FlowApprovalStatus.REJECTED, 'downgrade-without-approval')

        covering = tuple(
            approval for approval in approvals
            if (target_rank := self._rank(approval.target_classification)) is not None
            and target_rank >= record_level
        )
        if not covering:
            return result(FlowApprovalStatus.REJECTED, 'approval-target-below-egress')

        approval = covering[0]
        if not approval.justification:
            return result(FlowApprovalStatus.REJECTED, 'downgrade-without-justification',
                          approval=approval)
        return result(FlowApprovalStatus.APPROVED, 'approved-downgrade', approval=approval)

    def _collect_edges(self) -> tuple[_EdgeCandidate, ...]:
        edges: set[tuple[str, str]] = set()
        for source_ref, target_ref in self._dependency_edges(self._bom.dependencies):
            if source_ref in self._services_by_ref and target_ref in self._services_by_ref:
                edges.add((source_ref, target_ref))
        return tuple(
            _EdgeCandidate(source_ref=source_ref, target_ref=target_ref)
            for source_ref, target_ref in sorted(edges)
        )

    @staticmethod
    def _dependency_edges(dependencies: Iterable[Dependency]) -> Iterator[tuple[str, str]]:
        seen: set[tuple[str, str]] = set()
        stack = list(dependencies)
        visited: set[int] = set()
        while stack:
            dependency = stack.pop()
            if id(dependency) in visited:
                continue
            visited.add(id(dependency))
            source_ref = str(dependency.ref)
            for child in dependency.dependencies:
                target_ref = str(child.ref)
                pair = (source_ref, target_ref)
                if pair not in seen:
                    seen.add(pair)
                    yield pair
                stack.append(child)

    def inspect_egresses(self) -> tuple[EgressInspection, ...]:
        """Inspect every outbound declaration of every service."""
        return tuple(
            egress
            for service_ref in sorted(self._services_by_ref)
            for egress in self._egress_candidates(service_ref)
        )

    def inspect_edges(self) -> tuple[EdgeInspection, ...]:
        """Inspect every dependency edge whose endpoints are known services."""
        egresses_by_service = {
            service_ref: self._egress_candidates(service_ref)
            for service_ref in self._services_by_ref
        }
        return tuple(
            self._inspect_edge(edge, egresses_by_service) for edge in self._edge_candidates
        )

    def _inspect_edge(self, edge: _EdgeCandidate,
                      egresses_by_service: Mapping[str, tuple[EgressInspection, ...]]) -> EdgeInspection:
        source = self._services_by_ref[edge.source_ref]
        target = self._services_by_ref[edge.target_ref]
        source_records = self._records_of(edge.source_ref)
        target_records = self._records_of(edge.target_ref)

        def result(status: FlowApprovalStatus, reasons: Iterable[str], *,
                   egresses: tuple[EgressInspection, ...] = (),
                   ingress: tuple[FlowRecord, ...] = (),
                   matched: bool = False) -> EdgeInspection:
            return EdgeInspection(
                source_ref=edge.source_ref,
                source_name=source.name,
                target_ref=edge.target_ref,
                target_name=target.name,
                source_egresses=egresses,
                target_ingress=ingress,
                matched=matched,
                crosses_trust_boundary=target.x_trust_boundary,
                status=status,
                reasons=tuple(sorted(set(reasons))),
            )

        if not source_records:
            return result(FlowApprovalStatus.REVIEW, ('missing-flow-declaration:source',))
        if not target_records:
            return result(FlowApprovalStatus.REVIEW, ('missing-flow-declaration:target',))

        source_egresses = tuple(record for record in source_records if record.is_egress)
        source_unknown = tuple(record for record in source_records if record.is_unknown_direction)
        target_ingress = tuple(record for record in target_records if record.is_ingress)
        target_unknown = tuple(record for record in target_records if record.is_unknown_direction)

        if not source_egresses and not source_unknown:
            return result(FlowApprovalStatus.REJECTED, ('direction-mismatch:source',))
        if not target_ingress and not target_unknown:
            return result(FlowApprovalStatus.REJECTED, ('direction-mismatch:target',))

        target_labels = {record.normalized_classification for record in target_ingress}
        source_labels = {record.normalized_classification for record in source_egresses}
        matched_egresses = tuple(
            egress for egress in egresses_by_service[edge.source_ref]
            if egress.flow.normalized_classification in target_labels
        )
        matched_ingress = tuple(
            record for record in target_ingress
            if record.normalized_classification in source_labels
        )
        unknown_reasons = ('unknown-flow-direction',) if source_unknown or target_unknown else ()

        if not matched_egresses:
            # Both endpoints declared relevant directions, but no label is
            # shared. There is no declared flow for this edge, so a human must
            # supply one or confirm the edge carries nothing in scope.
            status = FlowApprovalStatus.UNKNOWN if unknown_reasons else FlowApprovalStatus.REVIEW
            reasons = ('no-matching-flow-declaration', *unknown_reasons)
            return result(status, reasons, ingress=target_ingress)

        status = _aggregate_status(tuple(egress.status for egress in matched_egresses))
        if unknown_reasons and status is not FlowApprovalStatus.REJECTED:
            status = FlowApprovalStatus.UNKNOWN
        reasons = tuple(
            reason for egress in matched_egresses for reason in egress.reasons
        ) + unknown_reasons
        return result(status, reasons, egresses=matched_egresses, ingress=matched_ingress, matched=True)

    def build_public_view(self) -> PublicFlowView:
        """Project approved egress at or below the public ceiling.

        Inbound declarations are never included. This is the mechanism that
        keeps restricted ingress out of a public view even when the same
        service publishes an approved public egress.
        """
        egresses = {(e.service_ref, e.flow.direction.value, e.flow.normalized_classification): e
                    for e in self.inspect_egresses()}
        records: list[PublicFlowRecord] = []
        excluded: list[ExcludedFlowRecord] = []
        for service_ref in sorted(self._services_by_ref):
            for flow in self._records_of(service_ref):
                if flow.is_egress:
                    egress = egresses.get(
                        (flow.service_ref, flow.direction.value, flow.normalized_classification))
                    if egress is not None and self._is_public_record(egress):
                        records.append(PublicFlowRecord(
                            service_ref=flow.service_ref,
                            service_name=flow.service_name,
                            classification=flow.classification,
                            destinations=egress.destinations,
                            approval_id=egress.approval.approval_id if egress.approval else None,
                        ))
                        continue
                    excluded.append(ExcludedFlowRecord(
                        flow=flow, reasons=self._egress_exclusion_reasons(egress)))
                elif flow.is_unknown_direction:
                    reasons = {'unknown-flow-direction'}
                    if flow.protection_level is None:
                        reasons.add('unknown-protection-level')
                    excluded.append(ExcludedFlowRecord(flow=flow, reasons=tuple(sorted(reasons))))
                else:
                    excluded.append(ExcludedFlowRecord(
                        flow=flow, reasons=self._ingress_exclusion_reasons(flow)))
        return PublicFlowView(
            ceiling=self._public_ceiling,
            records=tuple(sorted(records, key=lambda r: (
                r.service_ref, r.classification.casefold(), r.destinations))),
            excluded=tuple(sorted(excluded, key=lambda e: (
                e.flow.service_ref, e.flow.direction.value, e.flow.classification.casefold()))),
        )

    def _is_public_record(self, egress: EgressInspection) -> bool:
        return (
            egress.status is FlowApprovalStatus.APPROVED
            and egress.flow.protection_level is not None
            and egress.flow.protection_level <= self._ceiling_rank
        )

    def _egress_exclusion_reasons(self, egress: Optional[EgressInspection]) -> tuple[str, ...]:
        if egress is None:
            return ('unknown-flow-direction',)
        reasons = set(egress.reasons)
        if egress.status is not FlowApprovalStatus.APPROVED:
            reasons.add('egress-not-approved')
        if (egress.flow.protection_level is not None
                and egress.flow.protection_level > self._ceiling_rank):
            reasons.add('above-public-ceiling')
        return tuple(sorted(reasons))

    def _ingress_exclusion_reasons(self, flow: FlowRecord) -> tuple[str, ...]:
        reasons = {'inbound-not-egress'}
        if flow.protection_level is None:
            reasons.add('unknown-protection-level')
        elif flow.protection_level > self._ceiling_rank:
            reasons.add('above-public-ceiling')
        return tuple(sorted(reasons))

    def report(self) -> ServiceFlowApprovalReport:
        """Build the complete report."""
        egresses = self.inspect_egresses()
        egresses_by_service: dict[str, list[EgressInspection]] = {}
        for egress in egresses:
            egresses_by_service.setdefault(egress.service_ref, []).append(egress)
        services = tuple(
            ServiceFlowSummary(
                service_ref=service_ref,
                service_name=self._services_by_ref[service_ref].name,
                ingress=tuple(
                    record for record in self._records_of(service_ref) if record.is_ingress
                ),
                egresses=tuple(egresses_by_service.get(service_ref, ())),
            )
            for service_ref in sorted(self._services_by_ref)
        )
        return ServiceFlowApprovalReport(
            services=services,
            edges=self.inspect_edges(),
            public_view=self.build_public_view(),
        )


def _aggregate_status(statuses: Sequence[FlowApprovalStatus]) -> FlowApprovalStatus:
    for candidate in (FlowApprovalStatus.REJECTED, FlowApprovalStatus.UNKNOWN, FlowApprovalStatus.REVIEW):
        if candidate in statuses:
            return candidate
    return FlowApprovalStatus.APPROVED


def _iter_services(services: Iterable[Service]) -> Iterator[Service]:
    seen: set[int] = set()
    stack = list(services)
    while stack:
        service = stack.pop()
        if id(service) in seen:
            continue
        seen.add(id(service))
        yield service
        stack.extend(service.services)


def inspect_service_flows(bom: Bom, *,
                          protection_levels: Optional[Mapping[str, int]] = None,
                          public_ceiling: str = 'public') -> ServiceFlowApprovalReport:
    """Convenience wrapper around :class:`ServiceFlowApprover`."""
    return ServiceFlowApprover(
        bom, protection_levels=protection_levels, public_ceiling=public_ceiling).report()
