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

"""Offline, approval-aware risk reconciliation for CycloneDX BOMs.

The reviewer never performs network I/O itself. External material is obtained
through a parser/resolver supplied by the application, and that call happens
only after the approval policy accepts the reference.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Set, Tuple, Union, cast

from ..model import ExternalReference
from ..model.bom import Bom

LOCAL_BOM_LOCATION = '<local-bom>'


class ReferenceStatus(str, Enum):
    """Verification status for one external-reference occurrence."""

    VERIFIED = 'verified'
    APPROVAL_MISSING = 'approval_missing'
    APPROVAL_DENIED = 'approval_denied'
    RESOLVER_MISSING = 'resolver_missing'
    NOT_FOUND = 'not_found'
    READ_FAILED = 'read_failed'
    PARSE_FAILED = 'parse_failed'
    MATCH_FAILED = 'match_failed'
    UNVERIFIABLE = 'unverifiable'


class RiskState(str, Enum):
    """Aggregate risk state for one dependency branch."""

    CONFIRMED_RISK = 'confirmed_risk'
    CONFIRMED_RISK_WITH_GAP = 'confirmed_risk_with_gap'
    PENDING_REVIEW = 'pending_review'
    NO_KNOWN_RISK = 'no_known_risk'


class MaterialPickupStatus(str, Enum):
    FETCHED = 'fetched'
    FAILED = 'failed'
    BLOCKED = 'blocked'


class RiskReviewError(Exception):
    """Base error for risk review adapters."""


class MaterialNotFoundError(RiskReviewError):
    """Raised by an in-memory resolver when a location is absent."""


ApprovalResult = Union[bool, str, 'ApprovalDecision', None]
ApprovalChecker = Callable[[ExternalReference, str], ApprovalResult]
ParserLike = Union[Callable[[str], Any], Any]


@dataclass(frozen=True)
class ApprovalDecision:
    """Approval result for one external reference."""

    approved: bool
    reason_code: str = ReferenceStatus.APPROVAL_MISSING.value
    reason: str = ''
    status: str = ReferenceStatus.APPROVAL_MISSING.value

    @classmethod
    def allow(cls, reason: str = 'material is on the approval register') -> 'ApprovalDecision':
        return cls(
            approved=True,
            reason_code='approved',
            reason=reason,
            status=ReferenceStatus.VERIFIED.value,
        )

    @classmethod
    def missing(cls, location: str) -> 'ApprovalDecision':
        return cls(
            approved=False,
            reason_code=ReferenceStatus.APPROVAL_MISSING.value,
            reason=f'No approval record exists for {location}',
            status=ReferenceStatus.APPROVAL_MISSING.value,
        )

    @classmethod
    def deny(cls, location: str, reason: str = 'material is explicitly denied') -> 'ApprovalDecision':
        return cls(
            approved=False,
            reason_code=ReferenceStatus.APPROVAL_DENIED.value,
            reason=f'{location}: {reason}',
            status=ReferenceStatus.APPROVAL_DENIED.value,
        )

    def to_dict(self) -> Dict[str, Any]:
        return _json_dict(vars(self))


class ApprovalRegistry:
    """In-memory approval register suitable for offline tests and tools."""

    def __init__(self, approved_locations: Optional[Union[str, Iterable[str]]] = None) -> None:
        self._decisions: Dict[str, ApprovalDecision] = {}
        if approved_locations is None:
            return
        locations = [approved_locations] if isinstance(approved_locations, str) else approved_locations
        for location in locations:
            self.approve(location)

    def approve(self, location: str, reason: Optional[str] = None) -> 'ApprovalRegistry':
        self._decisions[location] = ApprovalDecision.allow(reason or f'{location} is explicitly approved')
        return self

    def deny(self, location: str, reason: Optional[str] = None) -> 'ApprovalRegistry':
        self._decisions[location] = ApprovalDecision.deny(location, reason or 'explicitly denied')
        return self

    def decide(self, reference: ExternalReference, location: str) -> ApprovalDecision:
        del reference
        return self._decisions.get(location, ApprovalDecision.missing(location))


class _CallableApproval:
    def __init__(self, callback: Callable[..., ApprovalResult]) -> None:
        self._callback = callback
        try:
            self._one_argument = len(inspect.signature(callback).parameters) == 1
        except (TypeError, ValueError):
            self._one_argument = False

    def decide(self, reference: ExternalReference, location: str) -> ApprovalDecision:
        if self._one_argument:
            result = self._callback(location)
        else:
            result = self._callback(reference, location)
        return _approval_decision(result, location)


@dataclass
class RiskFinding:
    """A confirmed risk fact, normally a CycloneDX vulnerability."""

    id: str
    kind: str = 'risk'
    severity: Optional[str] = None
    summary: Optional[str] = None
    source: str = LOCAL_BOM_LOCATION
    affected_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return _json_dict(vars(self))


@dataclass
class FetchRecord:
    """An actual parser pickup attempt."""

    location: str
    status: str = MaterialPickupStatus.FETCHED.value
    attempt: int = 1
    source_path: Optional[str] = None
    parser_called: bool = True
    error_type: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return _json_dict(vars(self))


@dataclass
class PickupRecord:
    """Pickup log entry recorded by :class:`InMemoryMaterialResolver`."""

    location: str
    status: str
    error: Optional[str] = None


@dataclass
class ExternalMaterial:
    """Material returned by an application parser.

    A parser may return a :class:`~cyclonedx.model.bom.Bom` directly; wrapping is
    only needed when the application also wants to supply risk facts or
    correlation metadata.
    """

    location: str
    bom: Optional[Bom] = field(default=None, repr=False)
    findings: List[RiskFinding] = field(default_factory=list)
    material_id: Optional[str] = None
    returned_location: Optional[str] = None
    matched_by: Optional[str] = None
    kind: str = 'material'
    hashes: Optional[Mapping[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        data = {key: value for key, value in vars(self).items() if key != 'bom'}
        data['has_bom'] = self.bom is not None
        return _json_dict(data)


@dataclass
class RelationshipCheck:
    """A locally inspectable dependency edge."""

    ref: str
    target_ref: Optional[str]
    bom_location: str
    path: str
    status: str = ReferenceStatus.VERIFIED.value
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return _json_dict(vars(self))


@dataclass
class ReferenceCheck:
    """Review result kept at one external-reference occurrence."""

    location: str
    reference_type: str
    path: str
    bom_location: str = LOCAL_BOM_LOCATION
    owner_kind: str = 'unknown'
    owner_ref: Optional[str] = None
    status: str = ReferenceStatus.UNVERIFIABLE.value
    reason_code: str = ReferenceStatus.UNVERIFIABLE.value
    reason: str = ''
    approved: bool = False
    parser_called: bool = False
    occurrence: int = 1
    duplicate: bool = False
    duplicate_of: Optional[str] = None
    matched_by: Optional[str] = None
    material_id: Optional[str] = None
    risk_ids: List[str] = field(default_factory=list)
    fetch: Optional[FetchRecord] = None

    @property
    def pending(self) -> bool:
        return self.status != ReferenceStatus.VERIFIED.value

    def to_dict(self) -> Dict[str, Any]:
        data = _json_dict(vars(self))
        data['review_status'] = self.status
        data['needs_review'] = self.pending
        return data


@dataclass
class MaterialEvidence:
    """An obtained external material matched back to its reference."""

    location: str
    matched_by: str
    status: str = ReferenceStatus.VERIFIED.value
    kind: str = 'material'
    material_id: Optional[str] = None
    source_path: Optional[str] = None
    owner_ref: Optional[str] = None
    risk_ids: List[str] = field(default_factory=list)
    reference_count: int = 1
    bom: Optional[Bom] = field(default=None, repr=False, compare=False)

    def to_dict(self) -> Dict[str, Any]:
        data = {key: value for key, value in vars(self).items() if key != 'bom'}
        data['has_bom'] = self.bom is not None
        return _json_dict(data)


@dataclass
class DependencyRisk:
    """Risk state and evidence for one dependency node in one BOM."""

    ref: str
    bom_location: str = LOCAL_BOM_LOCATION
    state: str = RiskState.PENDING_REVIEW.value
    complete: bool = False
    children: List[str] = field(default_factory=list)
    risks: List[RiskFinding] = field(default_factory=list)
    external_references: List[ReferenceCheck] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    gap_paths: List[str] = field(default_factory=list)

    @property
    def pending_references(self) -> List[ReferenceCheck]:
        return [reference for reference in self.external_references if reference.pending]

    @property
    def confirmed_risks(self) -> List[RiskFinding]:
        return list(self.risks)

    def to_dict(self) -> Dict[str, Any]:
        data = vars(self).copy()
        data['pending_references'] = self.pending_references
        data['confirmed_risk_ids'] = [risk.id for risk in self.risks]
        data['risk_status'] = self.state
        data['needs_review'] = self.state in {
            RiskState.PENDING_REVIEW.value,
            RiskState.CONFIRMED_RISK_WITH_GAP.value,
        }
        return _json_dict(data)


@dataclass
class RiskReviewReport:
    """Complete approval/risk reconciliation output."""

    relationships: List[RelationshipCheck] = field(default_factory=list)
    reference_reviews: List[ReferenceCheck] = field(default_factory=list)
    materials: List[MaterialEvidence] = field(default_factory=list)
    dependencies: List[DependencyRisk] = field(default_factory=list)
    fetch_log: List[FetchRecord] = field(default_factory=list)

    @property
    def locally_verified_relationships(self) -> List[RelationshipCheck]:
        return [item for item in self.relationships if item.status == ReferenceStatus.VERIFIED.value]

    @property
    def verified_relationships(self) -> List[RelationshipCheck]:
        return self.locally_verified_relationships

    @property
    def matched_external_materials(self) -> List[MaterialEvidence]:
        return list(self.materials)

    @property
    def verified_materials(self) -> List[MaterialEvidence]:
        return self.matched_external_materials

    @property
    def pending_references(self) -> List[ReferenceCheck]:
        return [item for item in self.reference_reviews if item.pending]

    @property
    def missing_approval_references(self) -> List[ReferenceCheck]:
        approval_statuses = {
            ReferenceStatus.APPROVAL_MISSING.value,
            ReferenceStatus.APPROVAL_DENIED.value,
        }
        return [item for item in self.reference_reviews if item.status in approval_statuses]

    @property
    def unverifiable_references(self) -> List[ReferenceCheck]:
        approval_statuses = {
            ReferenceStatus.APPROVAL_MISSING.value,
            ReferenceStatus.APPROVAL_DENIED.value,
        }
        return [item for item in self.pending_references if item.status not in approval_statuses]

    @property
    def unresolved_references(self) -> List[ReferenceCheck]:
        return self.pending_references

    def dependency(self, ref: str, bom_location: str = LOCAL_BOM_LOCATION) -> Optional[DependencyRisk]:
        return next(
            (item for item in self.dependencies if item.ref == ref and item.bom_location == bom_location),
            None,
        )

    def summary(self) -> Dict[str, int]:
        states = [item.state for item in self.dependencies]
        confirmed = states.count(RiskState.CONFIRMED_RISK.value)
        confirmed += states.count(RiskState.CONFIRMED_RISK_WITH_GAP.value)
        return {
            'locally_verified_relationships': len(self.locally_verified_relationships),
            'matched_external_materials': len(self.matched_external_materials),
            'pending_references': len(self.pending_references),
            'missing_approval_references': len(self.missing_approval_references),
            'unverifiable_references': len(self.unverifiable_references),
            'dependency_count': len(self.dependencies),
            'confirmed_risk_dependencies': confirmed,
            'pending_dependencies': states.count(RiskState.PENDING_REVIEW.value),
            'fetch_attempts': len(self.fetch_log),
            'failed_fetches': sum(
                1 for item in self.fetch_log if item.status != MaterialPickupStatus.FETCHED.value
            ),
        }

    def to_dict(self) -> Dict[str, Any]:
        return _json_dict({
            'summary': self.summary(),
            'risk_statuses': self.risk_statuses(),
            'locally_verified_relationships': self.locally_verified_relationships,
            'matched_external_materials': self.matched_external_materials,
            'pending_references': self.pending_references,
            'missing_approval_references': self.missing_approval_references,
            'unverifiable_references': self.unverifiable_references,
            # Compatibility aliases for consumers using shorter names.
            'local_relationships': self.relationships,
            'verified_materials': self.verified_materials,
            'unresolved_references': self.unresolved_references,
            'reference_reviews': self.reference_reviews,
            'dependencies': self.dependencies,
            'dependency_risks': self.dependencies,
            'fetch_log': self.fetch_log,
            'fetch_records': self.fetch_log,
        })

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    def as_dict(self) -> Dict[str, Any]:
        return self.to_dict()

    def risk_statuses(self) -> Dict[str, str]:
        """Map local refs (and namespaced external refs) to risk states."""
        return {
            item.ref
            if item.bom_location == LOCAL_BOM_LOCATION
            else f'{item.bom_location}::{item.ref}': item.state
            for item in self.dependencies
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        from json import dumps

        return dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)


class InMemoryMaterialResolver:
    """Offline parser/resolver with an inspectable pickup log."""

    def __init__(
        self,
        materials: Optional[Mapping[str, Any]] = None,
        *,
        fail_locations: Optional[Iterable[str]] = None,
    ) -> None:
        self.materials: Dict[str, Any] = dict(materials or {})
        self.fail_locations: Set[str] = set(fail_locations or [])
        self.pickup_log: List[PickupRecord] = []
        self.requested_locations: List[str] = []
        # Common test-double aliases.
        self.requests = self.requested_locations
        self.calls = self.requested_locations
        self.parse_calls = self.requested_locations

    def parse(self, location: str) -> Any:
        """Return seeded material or raise an offline-simulated failure."""
        self.requested_locations.append(location)
        if location in self.fail_locations:
            error = f'simulated read failure for {location}'
            self.pickup_log.append(PickupRecord(location, MaterialPickupStatus.FAILED.value, error))
            raise OSError(error)
        if location not in self.materials:
            error = f'no in-memory material registered for {location}'
            self.pickup_log.append(PickupRecord(location, MaterialPickupStatus.FAILED.value, error))
            raise MaterialNotFoundError(error)
        material = self.materials[location]
        if isinstance(material, BaseException):
            self.pickup_log.append(PickupRecord(location, MaterialPickupStatus.FAILED.value, str(material)))
            raise material
        if callable(material):
            material = material()
        self.pickup_log.append(PickupRecord(location, MaterialPickupStatus.FETCHED.value))
        return material

    def fail(self, location: str) -> None:
        """Make an already-approved location fail on the next review run."""
        self.fail_locations.add(location)

    def recover(self, location: str) -> None:
        self.fail_locations.discard(location)

    # Aliases for applications that name the boundary resolve/fetch/load.
    resolve = parse
    fetch = parse
    load = parse


@dataclass
class _RunState:
    relationships: List[RelationshipCheck] = field(default_factory=list)
    reference_reviews: List[ReferenceCheck] = field(default_factory=list)
    materials: List[MaterialEvidence] = field(default_factory=list)
    dependencies: Dict[Tuple[str, str], DependencyRisk] = field(default_factory=dict)
    fetch_log: List[FetchRecord] = field(default_factory=list)
    occurrences: Dict[str, int] = field(default_factory=dict)
    expanded_locations: Set[str] = field(default_factory=set)
    seen_edges: Set[Tuple[str, str, str]] = field(default_factory=set)
    bom_findings: Dict[str, List[RiskFinding]] = field(default_factory=dict)
    material_gap_paths: Dict[str, List[str]] = field(default_factory=dict)


class RiskReviewer:
    """Review a BOM using an application parser and an approval policy."""

    def __init__(
        self,
        parser: Optional[ParserLike] = None,
        *,
        resolver: Optional[ParserLike] = None,
        approval: Optional[Union[ApprovalRegistry, ApprovalChecker, Iterable[str]]] = None,
        approved_locations: Optional[Iterable[str]] = None,
        reference_types: Optional[Iterable[Any]] = None,
        include_services: bool = True,
    ) -> None:
        provider = parser if parser is not None else resolver
        self._parse = _as_parser(provider)
        if approval is None:
            approval = ApprovalRegistry(approved_locations)
        elif not hasattr(approval, 'decide') and not callable(approval):
            approval = ApprovalRegistry(approval)
        self._approval: Any = _as_approval(approval)
        self._reference_types = None if reference_types is None else {str(item) for item in reference_types}
        self._include_services = include_services

    def review(self, bom: Bom) -> RiskReviewReport:
        """Run one isolated review without mutating *bom*."""
        state = _RunState()
        self._review_bom(bom, LOCAL_BOM_LOCATION, 'bom', 'bom', (), state)
        for dependency in state.dependencies.values():
            _finalize_dependency(dependency)
        _propagate_dependency_graph(state)
        for dependency in state.dependencies.values():
            _finalize_dependency(dependency)
        return RiskReviewReport(
            relationships=sorted(state.relationships, key=lambda item: (item.bom_location, item.path)),
            reference_reviews=sorted(
                state.reference_reviews,
                key=lambda item: (item.bom_location, item.path, item.occurrence),
            ),
            materials=sorted(state.materials, key=lambda item: (item.location, item.source_path or '')),
            dependencies=sorted(state.dependencies.values(), key=lambda item: (item.bom_location, item.ref)),
            fetch_log=state.fetch_log,
        )

    def _review_bom(
        self,
        bom: Bom,
        bom_location: str,
        owner_kind: str,
        base_path: str,
        chain: Tuple[str, ...],
        state: _RunState,
    ) -> List[RiskFinding]:
        del owner_kind
        findings = _findings_from_bom(bom, bom_location)
        state.bom_findings[bom_location] = findings
        known_refs = _known_refs(bom)
        self._index_dependencies(bom, bom_location, known_refs, state)
        for finding in findings:
            for target_ref in finding.affected_refs:
                _add_findings(self._dependency(state, bom_location, target_ref), [finding])

        owners = _reference_owners(bom, include_services=self._include_services)
        for owner, owner_ref, owner_path, references in owners:
            dependency = self._dependency(state, bom_location, owner_ref) if owner_ref else None
            # External-reference repositories are SortedSets; preserve their
            # natural order so an index matches the serialized BOM position.
            ordered = list(references)
            for index, reference in enumerate(ordered):
                if self._reference_types is not None and str(reference.type) not in self._reference_types:
                    continue
                path = f'{owner_path}.externalReferences[{index}]'
                check = self._review_reference(
                    reference,
                    bom_location=bom_location,
                    owner_kind=owner,
                    owner_ref=owner_ref,
                    path=path,
                    chain=chain,
                    state=state,
                )
                state.reference_reviews.append(check)
                if dependency is not None:
                    dependency.external_references.append(check)
        return findings

    def _index_dependencies(
        self,
        bom: Bom,
        bom_location: str,
        known_refs: Set[str],
        state: _RunState,
    ) -> None:
        for dependency in sorted(bom.dependencies, key=lambda item: str(item.ref)):
            source_ref = _ref_str(dependency.ref)
            source = self._dependency(state, bom_location, source_ref)
            if source_ref not in known_refs:
                issue = f'dependency source {source_ref!r} is not a known local element'
                source.issues.append(issue)
            for child in sorted(dependency.dependencies, key=lambda item: str(item.ref)):
                target_ref = _ref_str(child.ref)
                edge_key = (bom_location, source_ref, target_ref)
                if edge_key in state.seen_edges:
                    continue
                state.seen_edges.add(edge_key)
                target = self._dependency(state, bom_location, target_ref)
                if target_ref not in source.children:
                    source.children.append(target_ref)
                source_known = source_ref in known_refs
                target_known = target_ref in known_refs
                verified = source_known and target_known
                reason = None if verified else (
                    f'local endpoint missing: source={source_known}, target={target_known}'
                )
                state.relationships.append(
                    RelationshipCheck(
                        ref=source_ref,
                        target_ref=target_ref,
                        bom_location=bom_location,
                        path=f'dependencies[{source_ref}].dependsOn[{target_ref}]',
                        status=ReferenceStatus.VERIFIED.value
                        if verified
                        else ReferenceStatus.UNVERIFIABLE.value,
                        reason=reason,
                    )
                )
                if reason:
                    target.issues.append(reason)

    def _review_reference(
        self,
        reference: ExternalReference,
        *,
        bom_location: str,
        owner_kind: str,
        owner_ref: Optional[str],
        path: str,
        chain: Tuple[str, ...],
        state: _RunState,
    ) -> ReferenceCheck:
        location = str(reference.url)
        state.occurrences[location] = state.occurrences.get(location, 0) + 1
        occurrence = state.occurrences[location]
        check = ReferenceCheck(
            location=location,
            reference_type=str(getattr(reference.type, 'value', reference.type)),
            path=path,
            bom_location=bom_location,
            owner_kind=owner_kind,
            owner_ref=owner_ref,
            occurrence=occurrence,
            duplicate=occurrence > 1,
            duplicate_of=location if occurrence > 1 else None,
        )
        decision = self._approval.decide(reference, location)
        check.approved = decision.approved
        if not decision.approved:
            check.status = decision.status
            check.reason_code = decision.reason_code
            check.reason = decision.reason
            return check

        if self._parse is None:
            check.status = ReferenceStatus.RESOLVER_MISSING.value
            check.reason_code = check.status
            check.reason = 'No application parser/resolver was supplied for offline pickup'
            return check

        record = FetchRecord(location=location, attempt=occurrence, source_path=path)
        state.fetch_log.append(record)
        try:
            raw_material = self._parse(location)
            material = _coerce_material(raw_material, location)
        except Exception as exc:
            _mark_fetch_failure(check, record, exc)
            return check

        record.status = MaterialPickupStatus.FETCHED.value
        check.parser_called = True
        check.fetch = record
        match_error = _match_material(location, material)
        if match_error:
            check.status = ReferenceStatus.MATCH_FAILED.value
            check.reason_code = ReferenceStatus.MATCH_FAILED.value
            check.reason = match_error
            return check

        check.status = ReferenceStatus.VERIFIED.value
        check.reason_code = ReferenceStatus.VERIFIED.value
        check.matched_by = material.matched_by
        check.material_id = material.material_id
        self._accept_material(material, check, owner_ref, path, chain, state)
        return check

    def _accept_material(
        self,
        material: ExternalMaterial,
        check: ReferenceCheck,
        owner_ref: Optional[str],
        path: str,
        chain: Tuple[str, ...],
        state: _RunState,
    ) -> None:
        del path
        evidence = MaterialEvidence(
            location=material.location,
            matched_by=material.matched_by or 'resolver-key',
            kind=material.kind,
            material_id=material.material_id,
            source_path=check.path,
            owner_ref=owner_ref,
            risk_ids=[finding.id for finding in material.findings],
            bom=material.bom,
        )
        state.materials.append(evidence)

        owner_dependency = None
        if owner_ref:
            owner_dependency = self._dependency(state, check.bom_location, owner_ref)
            _add_findings(owner_dependency, material.findings)

        if material.bom is None:
            check.risk_ids = [finding.id for finding in material.findings]
            return

        before_reference_count = len(state.reference_reviews)
        if material.location not in state.expanded_locations and material.location not in chain:
            state.expanded_locations.add(material.location)
            child_findings = self._review_bom(
                material.bom,
                material.location,
                'external-bom',
                f'external:{material.location}',
                chain + (material.location,),
                state,
            )
            new_checks = state.reference_reviews[before_reference_count:]
            state.material_gap_paths[material.location] = [
                f'{pending.bom_location} :: {pending.path}'
                for pending in new_checks
                if pending.pending
            ]
        else:
            child_findings = state.bom_findings.get(material.location, [])
        if owner_dependency is not None:
            _add_findings(owner_dependency, child_findings)
            for gap_path in state.material_gap_paths.get(material.location, []):
                if gap_path not in owner_dependency.gap_paths:
                    owner_dependency.gap_paths.append(gap_path)
        check.risk_ids = [finding.id for finding in child_findings]
        evidence.risk_ids = check.risk_ids

    @staticmethod
    def _dependency(state: _RunState, bom_location: str, ref: str) -> DependencyRisk:
        key = (bom_location, ref)
        if key not in state.dependencies:
            state.dependencies[key] = DependencyRisk(ref=ref, bom_location=bom_location)
        return state.dependencies[key]


def review_risks(
    bom: Bom,
    parser: Optional[ParserLike] = None,
    *,
    resolver: Optional[ParserLike] = None,
    approval: Optional[Union[ApprovalRegistry, ApprovalChecker, Iterable[str]]] = None,
    approved_locations: Optional[Iterable[str]] = None,
    reference_types: Optional[Iterable[Any]] = None,
) -> RiskReviewReport:
    """Functional entry point for an offline risk review."""
    return RiskReviewer(
        parser=parser,
        resolver=resolver,
        approval=approval,
        approved_locations=approved_locations,
        reference_types=reference_types,
    ).review(bom)


RiskReconciler = RiskReviewer
RiskAuditor = RiskReviewer
review_bom_risks = review_risks
audit_bom_risks = review_risks
InMemoryBomResolver = InMemoryMaterialResolver
InMemoryParser = InMemoryMaterialResolver
MemoryParser = InMemoryMaterialResolver
MemoryResolver = InMemoryMaterialResolver
DictMaterialResolver = InMemoryMaterialResolver


def _as_parser(provider: Optional[ParserLike]) -> Optional[Callable[[str], Any]]:
    if provider is None:
        return None
    for method_name in ('parse', 'resolve', 'fetch', 'load'):
        method = getattr(provider, method_name, None)
        if callable(method):
            return cast(Callable[[str], Any], method)
    if callable(provider):
        return provider
    raise TypeError('parser/resolver must be callable or implement parse(), resolve(), fetch(), or load()')


def _as_approval(approval: Union[ApprovalRegistry, ApprovalChecker, Iterable[str]]) -> Any:
    if hasattr(approval, 'decide') and callable(approval.decide):
        return approval
    if callable(approval):
        return _CallableApproval(approval)
    return ApprovalRegistry(approval)  # type: ignore[arg-type]


def _approval_decision(result: ApprovalResult, location: str) -> ApprovalDecision:
    if isinstance(result, ApprovalDecision):
        return result
    if result is None or result is False:
        return ApprovalDecision.missing(location)
    if result is True:
        return ApprovalDecision.allow()
    if isinstance(result, str):
        normalized = result.strip().lower()
        if normalized in {'approved', 'allow', 'allowed', 'true', 'yes'}:
            return ApprovalDecision.allow(result)
        return ApprovalDecision.deny(location, result)
    raise TypeError(f'unsupported approval result: {result!r}')


def _ref_str(ref: Any) -> str:
    value = getattr(ref, 'value', ref)
    if value is None:
        return ''
    return str(value)


def _known_refs(bom: Bom) -> Set[str]:
    refs: Set[str] = set()

    def add(element: Any) -> None:
        ref = _ref_str(getattr(element, 'bom_ref', None))
        if ref:
            refs.add(ref)

    if bom.metadata.component is not None:
        for component in bom.metadata.component.iter_all_nested_components(include_self=True):
            add(component)
    for component in bom.components:
        for nested in component.iter_all_nested_components(include_self=True):
            add(nested)
    for service in bom.services:
        add(service)
    for vulnerability in bom.vulnerabilities:
        add(vulnerability)
    return refs


def _reference_owners(
    bom: Bom,
    *,
    include_services: bool,
) -> Iterable[Tuple[str, Optional[str], str, Iterable[ExternalReference]]]:
    yield 'bom', None, 'bom', bom.external_references
    seen_components: Set[int] = set()
    if bom.metadata.component is not None:
        for component in bom.metadata.component.iter_all_nested_components(include_self=True):
            if id(component) in seen_components:
                continue
            seen_components.add(id(component))
            label = _ref_str(component.bom_ref) or component.name
            yield (
                'component',
                _ref_str(component.bom_ref) or None,
                f'metadata.component({label})',
                component.external_references,
            )
    for component in bom.components:
        for nested in component.iter_all_nested_components(include_self=True):
            if id(nested) in seen_components:
                continue
            seen_components.add(id(nested))
            label = _ref_str(nested.bom_ref) or nested.name
            yield (
                'component',
                _ref_str(nested.bom_ref) or None,
                f'components({label})',
                nested.external_references,
            )
    if include_services:
        for service in bom.services:
            label = _ref_str(service.bom_ref) or service.name
            yield (
                'service',
                _ref_str(service.bom_ref) or None,
                f'services({label})',
                service.external_references,
            )


def _findings_from_bom(bom: Bom, source: str) -> List[RiskFinding]:
    findings: List[RiskFinding] = []
    for vulnerability in bom.vulnerabilities:
        vulnerability_id = vulnerability.id or _ref_str(vulnerability.bom_ref) or 'unidentified-vulnerability'
        findings.append(
            RiskFinding(
                id=vulnerability_id,
                kind='vulnerability',
                severity=_vulnerability_severity(vulnerability),
                summary=vulnerability.description,
                source=source,
                affected_refs=[str(target.ref) for target in vulnerability.affects],
            )
        )
    return findings


def _vulnerability_severity(vulnerability: Any) -> Optional[str]:
    for rating in vulnerability.ratings:
        severity = getattr(rating, 'severity', None)
        if severity is not None:
            return str(getattr(severity, 'value', severity))
    return None


def _add_findings(dependency: DependencyRisk, findings: Iterable[RiskFinding]) -> None:
    existing = {(item.id, item.source) for item in dependency.risks}
    for finding in findings:
        key = (finding.id, finding.source)
        if key not in existing:
            dependency.risks.append(finding)
            existing.add(key)


def _finalize_dependency(dependency: DependencyRisk) -> None:
    pending = dependency.pending_references
    dependency.complete = not pending and not dependency.issues and not dependency.gap_paths
    has_gap = bool(pending or dependency.issues or dependency.gap_paths)
    if dependency.risks and has_gap:
        dependency.state = RiskState.CONFIRMED_RISK_WITH_GAP.value
    elif dependency.risks:
        dependency.state = RiskState.CONFIRMED_RISK.value
    elif has_gap:
        dependency.state = RiskState.PENDING_REVIEW.value
    else:
        dependency.state = RiskState.NO_KNOWN_RISK.value


def _propagate_dependency_graph(state: _RunState) -> None:
    """Copy confirmed facts and gap paths from child branches to parents."""
    for _ in range(max(1, len(state.dependencies))):
        changed = False
        for relationship in state.relationships:
            parent = state.dependencies.get((relationship.bom_location, relationship.ref))
            child = state.dependencies.get((relationship.bom_location, relationship.target_ref or ''))
            if parent is None or child is None or parent is child:
                continue
            risk_count_before = len(parent.risks)
            _add_findings(parent, child.risks)
            changed = changed or len(parent.risks) != risk_count_before
            child_gaps = list(child.gap_paths)
            child_gaps.extend(
                f'{check.bom_location} :: {check.path}' for check in child.pending_references
            )
            if child.state == RiskState.PENDING_REVIEW.value and not child_gaps:
                child_gaps.append(f'{child.bom_location} :: dependencies({child.ref})')
            for gap in child_gaps:
                scoped_gap = f'child {child.ref}: {gap}'
                if scoped_gap not in parent.gap_paths:
                    parent.gap_paths.append(scoped_gap)
                    changed = True
        if not changed:
            return


def _mark_fetch_failure(check: ReferenceCheck, record: FetchRecord, exc: Exception) -> None:
    if isinstance(exc, (MaterialNotFoundError, FileNotFoundError)):
        status = ReferenceStatus.NOT_FOUND.value
    elif isinstance(exc, OSError):
        status = ReferenceStatus.READ_FAILED.value
    else:
        status = ReferenceStatus.PARSE_FAILED.value
    record.status = MaterialPickupStatus.FAILED.value
    record.error_type = type(exc).__name__
    record.error = str(exc)
    check.parser_called = True
    check.fetch = record
    check.status = status
    check.reason_code = status
    check.reason = f'Approved material could not be verified ({type(exc).__name__}): {exc}'


def _coerce_material(raw: ParserLike, location: str) -> ExternalMaterial:
    if isinstance(raw, ExternalMaterial):
        raw.location = raw.location or location
        return raw
    if isinstance(raw, Bom):
        return ExternalMaterial(location=location, bom=raw, kind='cyclonedx-bom')
    if isinstance(raw, Mapping):
        bom = raw.get('bom')
        findings = _coerce_findings(raw.get('findings') or raw.get('risks') or [])
        hashes = raw.get('hashes')
        return ExternalMaterial(
            location=str(raw.get('location') or location),
            returned_location=raw.get('returned_location'),
            bom=bom if isinstance(bom, Bom) else None,
            findings=findings,
            material_id=raw.get('material_id') or raw.get('id'),
            kind=str(raw.get('kind') or ('cyclonedx-bom' if isinstance(bom, Bom) else 'material')),
            hashes=hashes if isinstance(hashes, Mapping) else None,
        )

    bom = getattr(raw, 'bom', None)
    risk_values = getattr(raw, 'findings', None) or getattr(raw, 'risks', None) or []
    returned_location = getattr(raw, 'returned_location', None)
    material_id = getattr(raw, 'material_id', None) or getattr(raw, 'id', None)
    if bom is not None or risk_values:
        return ExternalMaterial(
            location=str(getattr(raw, 'location', location) or location),
            returned_location=str(returned_location) if returned_location else None,
            bom=bom if isinstance(bom, Bom) else None,
            findings=_coerce_findings(risk_values),
            material_id=str(material_id) if material_id else None,
            kind=str(getattr(raw, 'kind', 'material')),
        )
    if raw is None:
        raise MaterialNotFoundError(f'parser returned no material for {location}')
    return ExternalMaterial(location=location, kind=type(raw).__name__)


def _coerce_findings(values: Any) -> List[RiskFinding]:
    findings: List[RiskFinding] = []
    if isinstance(values, (str, RiskFinding, Mapping)):
        values = [values]
    for value in values or []:
        if isinstance(value, RiskFinding):
            findings.append(value)
        elif isinstance(value, str):
            findings.append(RiskFinding(id=value))
        elif isinstance(value, Mapping):
            raw_affected = value.get('affected_refs') or value.get('affects') or []
            findings.append(
                RiskFinding(
                    id=str(value.get('id') or value.get('risk_id') or value.get('cve') or 'unidentified-risk'),
                    kind=str(value.get('kind') or value.get('type') or 'risk'),
                    severity=value.get('severity'),
                    summary=value.get('summary') or value.get('description'),
                    source=str(value.get('source') or 'parser'),
                    affected_refs=[str(item) for item in raw_affected],
                )
            )
        else:
            risk_id = getattr(value, 'id', None) or getattr(value, 'risk_id', None) or 'unidentified-risk'
            findings.append(RiskFinding(id=str(risk_id)))
    return findings


def _match_material(requested_location: str, material: ExternalMaterial) -> Optional[str]:
    if material.returned_location and material.returned_location != requested_location:
        return (
            f'Parser returned material for {material.returned_location!r}, '
            f'but reference requested {requested_location!r}'
        )

    if material.bom is not None and requested_location.startswith('urn:cdx:'):
        bom_link = f"urn:cdx:{material.bom.serial_number}/{material.bom.version}"
        if not requested_location.startswith(bom_link):
            return f'BOM identity {bom_link} does not match BOM-Link {requested_location}'
        material.material_id = material.material_id or bom_link
        material.matched_by = 'bom-link'
        return None

    if material.material_id:
        material.matched_by = 'material-id'
        return None
    if material.bom is not None:
        material.material_id = f"urn:cdx:{material.bom.serial_number}/{material.bom.version}"
    material.matched_by = 'resolver-key+bom-identity' if material.bom is not None else 'resolver-key'
    return None


def _json_dict(value: Dict[str, Any]) -> Dict[str, Any]:
    encoded = _jsonable(value)
    return cast(Dict[str, Any], encoded)


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, 'to_dict'):
        return value.to_dict()
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    if isinstance(value, MappingProxyType):
        return _jsonable(dict(value))
    return value
