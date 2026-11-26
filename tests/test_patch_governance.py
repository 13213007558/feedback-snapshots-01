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

"""Regression tests for patch-governance risk conclusions.

Two component instances share the same package coordinate but live in different
scopes and have distinct bom-refs.  A scanner patch upgrades only one instance;
the remaining old instance gets its dependency edge added late.  The tests derive
the risk conclusion from the serialized JSON/XML only, resolving targets by the
actual component reference and evaluating versions against the declared version
domain.

A deliberately wrong test double closes the impact by package coordinate alone.
Its assertion failure is pinned to the actual dependency edge that still reaches
the old, affected instance.  A control where both instances are upgraded proves
that closing is still possible when the actual components and relations allow it.
"""

import json
from dataclasses import dataclass
from typing import Any, Literal, Optional
from unittest import TestCase
from xml.etree.ElementTree import Element, fromstring as xml_fromstring

from packageurl import PackageURL

from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentScope, ComponentType
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.impact_analysis import ImpactAnalysisAffectedStatus
from cyclonedx.model.vulnerability import BomTarget, BomTargetVersionRange, Vulnerability
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion

_PACKAGE_TYPE = 'pypi'
_PACKAGE_NAME = 'acme-lib'
_OLD_VERSION = '1.5.0'
_PATCHED_VERSION = '2.0.0'
_AFFECTED_RANGE = 'vers:pypi/<2.0.0'
_VULNERABILITY_ID = 'CVE-2026-0001'

_APP_REF = 'component:app'
_RUNTIME_REF = 'component:acme-lib/runtime'
_TOOLING_REF = 'component:acme-lib/tooling'
_MISSING_REF = 'component:acme-lib/absent'

_FORMATS = (OutputFormat.JSON, OutputFormat.XML)


@dataclass(frozen=True)
class _ComponentRecord:
    ref: str
    version: Optional[str]
    purl: Optional[str]
    scope: Optional[str]


@dataclass(frozen=True, order=True)
class _DependencyEdge:
    parent: str
    child: str


@dataclass(frozen=True)
class _ImpactRecord:
    ref: str
    affected_range: str
    status: str


@dataclass(frozen=True)
class _Inventory:
    root_ref: str
    components: dict[str, _ComponentRecord]
    edges: frozenset[_DependencyEdge]
    impacts: tuple[_ImpactRecord, ...]


@dataclass(frozen=True)
class _Conclusion:
    ref: str
    verdict: Literal['closed', 'open', 'unresolved']
    open_edges: tuple[_DependencyEdge, ...]
    reason: str


def _purl(version: str) -> PackageURL:
    return PackageURL(type=_PACKAGE_TYPE, name=_PACKAGE_NAME, version=version)


def _make_instance(ref: str, scope: ComponentScope) -> Component:
    return Component(
        name=_PACKAGE_NAME,
        version=_OLD_VERSION,
        type=ComponentType.LIBRARY,
        bom_ref=ref,
        scope=scope,
        purl=_purl(_OLD_VERSION),
    )


def make_patch_governance_bom(
        *,
        patched_refs: frozenset[str] = frozenset(),
        affected_ref: str = _TOOLING_REF,
        late_dependency: bool = True,
) -> Bom:
    app = Component(name='app', version='7.0.0', type=ComponentType.APPLICATION, bom_ref=_APP_REF)
    runtime = _make_instance(_RUNTIME_REF, ComponentScope.REQUIRED)
    tooling = _make_instance(_TOOLING_REF, ComponentScope.OPTIONAL)
    bom = Bom(metadata=BomMetaData(component=app), components=[runtime, tooling])
    bom.dependencies.add(Dependency(app.bom_ref, [Dependency(runtime.bom_ref)]))
    bom.vulnerabilities.add(Vulnerability(
        bom_ref=_VULNERABILITY_ID,
        id=_VULNERABILITY_ID,
        affects=[BomTarget(ref=affected_ref, versions=[BomTargetVersionRange(
            range=_AFFECTED_RANGE,
            status=ImpactAnalysisAffectedStatus.AFFECTED,
        )])],
    ))
    for ref in patched_refs:
        _patch_instance(bom, ref)
    if late_dependency:
        # A separate dependency record, added after the patch: the old scope's edge
        # must survive JSON flattening and XML serialization alike.
        bom.dependencies.add(Dependency(app.bom_ref, [Dependency(tooling.bom_ref)]))
    return bom


def _patch_instance(bom: Bom, ref: str) -> None:
    components = []
    for component in bom.components:
        if component.bom_ref.value == ref:
            component = Component(
                name=component.name,
                version=_PATCHED_VERSION,
                type=component.type,
                bom_ref=component.bom_ref,
                scope=component.scope,
                purl=_purl(_PATCHED_VERSION),
            )
        components.append(component)
    bom.components = components


def _serialize(bom: Bom, fmt: OutputFormat) -> str:
    return make_outputter(bom, fmt, SchemaVersion.V1_7).output_as_string(indent=2)


def _parse_inventory(text: str, fmt: OutputFormat) -> _Inventory:
    if fmt is OutputFormat.JSON:
        return _parse_json_inventory(text)
    return _parse_xml_inventory(text)


def _parse_json_inventory(text: str) -> _Inventory:
    document = json.loads(text)
    components = {
        component['bom-ref']: _ComponentRecord(
            ref=component['bom-ref'],
            version=component.get('version'),
            purl=component.get('purl'),
            scope=component.get('scope'),
        )
        for component in document.get('components', [])
    }
    edges = frozenset(
        _DependencyEdge(parent=dependency['ref'], child=child)
        for dependency in document.get('dependencies', [])
        for child in dependency.get('dependsOn', [])
    )
    impacts = tuple(
        _ImpactRecord(ref=target['ref'], affected_range=version.get('range', ''), status=version.get('status', ''))
        for vulnerability in document.get('vulnerabilities', [])
        for target in vulnerability.get('affects', [])
        for version in target.get('versions', [])
    )
    return _Inventory(
        root_ref=document['metadata']['component']['bom-ref'],
        components=components,
        edges=edges,
        impacts=impacts,
    )


def _xml_namespace(root: Element) -> str:
    return root.tag[:root.tag.index('}') + 1] if root.tag.startswith('{') else ''


def _parse_xml_inventory(text: str) -> _Inventory:
    root = xml_fromstring(text)
    ns = _xml_namespace(root)
    metadata_component = root.find(f'{ns}metadata/{ns}component')
    if metadata_component is None:
        raise AssertionError('XML inventory has no metadata component')
    components = {
        component.attrib['bom-ref']: _ComponentRecord(
            ref=component.attrib['bom-ref'],
            version=component.findtext(f'{ns}version'),
            purl=component.findtext(f'{ns}purl'),
            scope=component.findtext(f'{ns}scope'),
        )
        for component in root.findall(f'{ns}components/{ns}component')
    }
    edges = frozenset(
        _DependencyEdge(parent=dependency.attrib['ref'], child=child.attrib['ref'])
        for dependency in root.findall(f'{ns}dependencies/{ns}dependency')
        for child in dependency.findall(f'{ns}dependency')
    )
    impacts = tuple(
        _ImpactRecord(
            ref=target.findtext(f'{ns}ref') or '',
            affected_range=version.findtext(f'{ns}range') or '',
            status=version.findtext(f'{ns}status') or '',
        )
        for target in root.findall(f'{ns}vulnerabilities/{ns}vulnerability/{ns}affects/{ns}target')
        for version in target.findall(f'{ns}versions/{ns}version')
    )
    return _Inventory(
        root_ref=metadata_component.attrib['bom-ref'],
        components=components,
        edges=edges,
        impacts=impacts,
    )


def _package_coordinate(purl: Optional[str]) -> tuple[str, Optional[str], str]:
    if not purl:
        raise AssertionError('component has no package coordinate')
    parsed = PackageURL.from_string(purl)
    return parsed.type, parsed.namespace, parsed.name


def _version_key(version: str) -> tuple[int, ...]:
    """Minimal numeric ordering for the dotted versions used by this fixture."""
    return tuple(int(part) for part in version.split('.'))


def _version_in_domain(version: str, affected_range: str) -> bool:
    prefix = 'vers:'
    if not affected_range.startswith(prefix):
        raise AssertionError(f'not a package-url version range: {affected_range!r}')
    _, _, constraints = affected_range.partition('/')
    if not constraints:
        raise AssertionError(f'package-url version range has no constraints: {affected_range!r}')
    candidate = _version_key(version)
    for constraint in constraints.split(','):
        operator = next((op for op in ('<=', '>=', '<', '>', '==') if constraint.startswith(op)), None)
        if operator is None:
            raise AssertionError(f'unsupported version constraint: {constraint!r}')
        bound = _version_key(constraint[len(operator):])
        within: Any
        if operator == '<':
            within = candidate < bound
        elif operator == '<=':
            within = candidate <= bound
        elif operator == '>':
            within = candidate > bound
        elif operator == '>=':
            within = candidate >= bound
        else:
            within = candidate == bound
        if not within:
            return False
    return True


def _reachable_refs(inventory: _Inventory) -> frozenset[str]:
    reachable = {inventory.root_ref}
    pending = [inventory.root_ref]
    while pending:
        parent = pending.pop()
        for edge in inventory.edges:
            if edge.parent == parent and edge.child not in reachable:
                reachable.add(edge.child)
                pending.append(edge.child)
    return frozenset(reachable)


def _conclude_target(inventory: _Inventory, target: _ImpactRecord) -> _Conclusion:
    component = inventory.components.get(target.ref)
    if component is None:
        return _Conclusion(target.ref, 'unresolved', (), 'target bom-ref is absent from components')
    if not component.version:
        return _Conclusion(target.ref, 'unresolved', (), 'target component has no version')
    if not _version_in_domain(component.version, target.affected_range):
        return _Conclusion(
            target.ref, 'closed', (),
            f'version {component.version} is outside affected domain {target.affected_range}',
        )
    reachable = _reachable_refs(inventory)
    open_edges = tuple(sorted(
        (edge for edge in inventory.edges if edge.child == target.ref and edge.parent in reachable),
        key=lambda edge: (edge.parent, edge.child),
    ))
    if not open_edges:
        return _Conclusion(
            target.ref, 'unresolved', (),
            f'version {component.version} is inside {target.affected_range}, '
            'but no reachable dependency edge declares exposure',
        )
    return _Conclusion(
        target.ref, 'open', open_edges,
        f'version {component.version} is inside {target.affected_range} and reachable',
    )


class _PackageCoordinateOnlyClosure:
    """Wrong-by-design test double: closes an impact by package coordinate only.

    It ignores per-instance bom-refs, scopes and dependency edges.  It finds the
    newest version among all components sharing the target's package coordinate
    and declares the impact closed when that newest version is outside the
    affected domain.
    """

    @staticmethod
    def conclude(inventory: _Inventory, target: _ImpactRecord) -> _Conclusion:
        component = inventory.components.get(target.ref)
        if component is None:
            return _Conclusion(target.ref, 'unresolved', (), 'coordinate lookup found no target')
        if not component.purl:
            return _Conclusion(target.ref, 'unresolved', (), 'target has no package coordinate')
        coordinate = _package_coordinate(component.purl)
        versions = [
            candidate.version
            for candidate in inventory.components.values()
            if candidate.version and candidate.purl and _package_coordinate(candidate.purl) == coordinate
        ]
        if not versions:
            return _Conclusion(target.ref, 'unresolved', (), 'coordinate lookup found no versions')
        newest = max(versions, key=_version_key)
        if not _version_in_domain(newest, target.affected_range):
            return _Conclusion(target.ref, 'closed', (), f'newest coordinate version {newest} is outside the domain')
        return _Conclusion(target.ref, 'open', (), f'newest coordinate version {newest} is inside the domain')


def _outcome(conclusion: _Conclusion) -> tuple[str, tuple[_DependencyEdge, ...]]:
    return conclusion.verdict, conclusion.open_edges


class TestPatchGovernanceRegressions(TestCase):

    def _inventory(
            self, fmt: OutputFormat, *,
            patched_refs: frozenset[str],
            affected_ref: str = _TOOLING_REF,
            late_dependency: bool = True,
    ) -> _Inventory:
        bom = make_patch_governance_bom(
            patched_refs=patched_refs,
            affected_ref=affected_ref,
            late_dependency=late_dependency,
        )
        return _parse_inventory(_serialize(bom, fmt), fmt)

    def test_json_and_xml_serialize_the_same_governance_evidence(self) -> None:
        bom = make_patch_governance_bom(patched_refs=frozenset({_RUNTIME_REF}))
        json_inventory = _parse_inventory(_serialize(bom, OutputFormat.JSON), OutputFormat.JSON)
        xml_inventory = _parse_inventory(_serialize(bom, OutputFormat.XML), OutputFormat.XML)
        self.assertEqual(json_inventory, xml_inventory)

    def test_instances_keep_distinct_refs_and_late_old_scope_edge(self) -> None:
        for fmt in _FORMATS:
            with self.subTest(fmt=fmt.name):
                inventory = self._inventory(fmt, patched_refs=frozenset({_RUNTIME_REF}))
                runtime = inventory.components[_RUNTIME_REF]
                tooling = inventory.components[_TOOLING_REF]
                self.assertNotEqual(runtime.ref, tooling.ref)
                self.assertEqual(_package_coordinate(runtime.purl), _package_coordinate(tooling.purl))
                self.assertEqual(_PATCHED_VERSION, runtime.version)
                self.assertEqual(_OLD_VERSION, tooling.version)
                self.assertEqual(ComponentScope.REQUIRED.value, runtime.scope)
                self.assertEqual(ComponentScope.OPTIONAL.value, tooling.scope)
                self.assertEqual(_PATCHED_VERSION, PackageURL.from_string(runtime.purl or '').version)
                self.assertEqual(_OLD_VERSION, PackageURL.from_string(tooling.purl or '').version)
                self.assertIn(_DependencyEdge(_APP_REF, _RUNTIME_REF), inventory.edges)
                self.assertIn(_DependencyEdge(_APP_REF, _TOOLING_REF), inventory.edges)

    def test_latest_old_and_missing_verdicts_are_distinguishable(self) -> None:
        for fmt in _FORMATS:
            with self.subTest(fmt=fmt.name):
                inventory = self._inventory(fmt, patched_refs=frozenset({_RUNTIME_REF}))
                self.assertEqual(1, len(inventory.impacts))
                recorded = inventory.impacts[0]
                self.assertEqual(_TOOLING_REF, recorded.ref)
                self.assertEqual(ImpactAnalysisAffectedStatus.AFFECTED.value, recorded.status)

                latest = _conclude_target(
                    inventory,
                    _ImpactRecord(_RUNTIME_REF, recorded.affected_range, recorded.status),
                )
                old = _conclude_target(inventory, recorded)
                missing = _conclude_target(
                    inventory,
                    _ImpactRecord(_MISSING_REF, recorded.affected_range, recorded.status),
                )

                self.assertEqual('closed', latest.verdict)
                self.assertEqual((), latest.open_edges)
                self.assertEqual('open', old.verdict)
                self.assertEqual((_DependencyEdge(_APP_REF, _TOOLING_REF),), old.open_edges)
                self.assertEqual('unresolved', missing.verdict)
                self.assertEqual((), missing.open_edges)
                self.assertEqual(3, len({latest.verdict, old.verdict, missing.verdict}))

    def test_coordinate_only_double_assertion_fails_at_old_scope_edge(self) -> None:
        for fmt in _FORMATS:
            with self.subTest(fmt=fmt.name):
                inventory = self._inventory(fmt, patched_refs=frozenset({_RUNTIME_REF}))
                target = inventory.impacts[0]
                actual = _conclude_target(inventory, target)
                double = _PackageCoordinateOnlyClosure.conclude(inventory, target)

                self.assertEqual('closed', double.verdict)
                self.assertEqual('open', actual.verdict)
                self.assertEqual((_DependencyEdge(_APP_REF, _TOOLING_REF),), actual.open_edges)

                with self.assertRaises(AssertionError) as caught:
                    self.assertEqual(
                        _outcome(actual), _outcome(double),
                        f'{fmt.name}: package-coordinate-only closure must not close the risk; '
                        f'the actual old-scope dependency edge is {actual.open_edges}',
                    )
                message = str(caught.exception)
                self.assertIn('old-scope dependency edge', message)
                self.assertIn(_TOOLING_REF, message)
                self.assertIn(_APP_REF, message)

    def test_control_both_instances_patched_allows_closure(self) -> None:
        for fmt in _FORMATS:
            with self.subTest(fmt=fmt.name):
                inventory = self._inventory(
                    fmt,
                    patched_refs=frozenset({_RUNTIME_REF, _TOOLING_REF}),
                )
                self.assertEqual(_PATCHED_VERSION, inventory.components[_RUNTIME_REF].version)
                self.assertEqual(_PATCHED_VERSION, inventory.components[_TOOLING_REF].version)
                self.assertIn(_DependencyEdge(_APP_REF, _TOOLING_REF), inventory.edges)

                actual = _conclude_target(inventory, inventory.impacts[0])
                double = _PackageCoordinateOnlyClosure.conclude(inventory, inventory.impacts[0])
                self.assertEqual('closed', actual.verdict)
                self.assertEqual((), actual.open_edges)
                self.assertEqual('closed', double.verdict)
                self.assertEqual(_outcome(actual), _outcome(double))

    def test_late_dependency_record_is_the_edge_to_the_old_scope_instance(self) -> None:
        for fmt in _FORMATS:
            with self.subTest(fmt=fmt.name):
                early = self._inventory(
                    fmt,
                    patched_refs=frozenset({_RUNTIME_REF}),
                    late_dependency=False,
                )
                late = self._inventory(
                    fmt,
                    patched_refs=frozenset({_RUNTIME_REF}),
                    late_dependency=True,
                )
                edge = _DependencyEdge(_APP_REF, _TOOLING_REF)
                self.assertNotIn(edge, early.edges)
                self.assertIn(edge, late.edges)
                self.assertEqual('unresolved', _conclude_target(early, early.impacts[0]).verdict)
                self.assertEqual('open', _conclude_target(late, late.impacts[0]).verdict)
                self.assertEqual((edge,), _conclude_target(late, late.impacts[0]).open_edges)
