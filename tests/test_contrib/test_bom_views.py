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

from json import loads as json_loads
from typing import Any
from unittest import TestCase

from packageurl import PackageURL

from cyclonedx.contrib.bom.views import (
    RESTRICTED_COMPONENT_PROPERTY,
    BomViewRedactor,
    collect_relationship_report,
    is_restricted_component,
    make_bom_views,
)
from cyclonedx.exception import CycloneDxException
from cyclonedx.exception.model import BomIdentityLeakException, BomReferenceIntegrityException
from cyclonedx.model import ExternalReference, ExternalReferenceType, Property, XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.component_evidence import ComponentEvidence, Occurrence
from cyclonedx.model.contact import OrganizationalEntity
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.impact_analysis import ImpactAnalysisState
from cyclonedx.model.vulnerability import BomTarget, Vulnerability, VulnerabilityAnalysis
from cyclonedx.schema import SchemaVersion


def _restricted(name: str, bom_ref: str, **kwargs: Any) -> Component:
    return Component(
        name=name,
        bom_ref=bom_ref,
        type=ComponentType.LIBRARY,
        properties=[Property(name=RESTRICTED_COMPONENT_PROPERTY, value='true')],
        **kwargs,
    )


class TestRestrictedMarker(TestCase):

    def test_marker_true(self) -> None:
        self.assertTrue(is_restricted_component(_restricted('x', 'x')))

    def test_marker_false_values(self) -> None:
        for value in ('false', '0', '', 'no', None):
            component = Component(
                name='x', bom_ref='x',
                properties=[Property(name=RESTRICTED_COMPONENT_PROPERTY, value=value)],
            )
            self.assertFalse(is_restricted_component(component), repr(value))


class TestRelationshipReport(TestCase):

    def test_collects_edges_and_targets(self) -> None:
        app = Component(name='app', bom_ref='app', type=ComponentType.APPLICATION)
        lib = Component(name='lib', bom_ref='lib')
        bom = Bom(components=[app, lib])
        bom.metadata.component = app
        bom.dependencies = [Dependency(app.bom_ref, [Dependency(lib.bom_ref)])]
        bom.vulnerabilities = [Vulnerability(id='CVE-1', bom_ref='v1', affects=[BomTarget(ref='lib')])]
        report = collect_relationship_report(bom)
        self.assertEqual(frozenset(('app', 'lib')), report.component_refs)
        self.assertEqual(frozenset((('app', 'lib'),)), report.dependency_edges)
        self.assertEqual(frozenset((('CVE-1', frozenset(('lib',))),)), report.vulnerability_targets)
        self.assertTrue(report.is_complete)

    def test_reports_unresolved_and_duplicate(self) -> None:
        bom = Bom(components=[Component(name='a', bom_ref='same'), Component(name='b', bom_ref='same')])
        bom.dependencies = [Dependency(bom.components[0].bom_ref, [Dependency(BomRef('missing'))])]
        report = collect_relationship_report(bom)
        self.assertIn('same', report.duplicate_refs)
        self.assertIn('missing', report.unresolved_refs)
        self.assertFalse(report.is_complete)

    def test_nested_dependency_edges_are_flattened(self) -> None:
        a = Component(name='a', bom_ref='a')
        b = Component(name='b', bom_ref='b')
        c = Component(name='c', bom_ref='c')
        bom = Bom(components=[a, b, c])
        bom.dependencies = [Dependency(
            a.bom_ref,
            [Dependency(b.bom_ref, [Dependency(c.bom_ref)])],
        )]
        report = collect_relationship_report(bom)
        self.assertEqual(frozenset((('a', 'b'), ('b', 'c'))), report.dependency_edges)


class TestBomViews(TestCase):

    @staticmethod
    def _make_bom() -> Bom:
        internal = _restricted(
            'internal-auth',
            'internal-auth',
            group='corp',
            version='1.0.0',
            purl=PackageURL(type='pypi', name='internal-auth', version='1.0.0'),
            supplier=OrganizationalEntity(name='Corp Secrets Inc'),
            evidence=ComponentEvidence(occurrences=[Occurrence(location='/srv/secret/auth.py')]),
            external_references=[ExternalReference(
                type=ExternalReferenceType.VCS, url=XsUri('https://git.internal.example/auth'))],
        )
        public = Component(name='public-lib', version='2.0.0', bom_ref='public-lib')
        app = Component(name='app', bom_ref='app', type=ComponentType.APPLICATION)
        bom = Bom(components=[internal, public])
        bom.metadata.component = app
        bom.dependencies = [
            Dependency(app.bom_ref, [Dependency(internal.bom_ref, [Dependency(public.bom_ref)])]),
            Dependency(public.bom_ref),
        ]
        bom.vulnerabilities = [Vulnerability(
            id='CVE-2026-0001', bom_ref='vuln-1',
            description='found in internal-auth at https://git.internal.example/auth',
            affects=[BomTarget(ref='internal-auth')],
            analysis=VulnerabilityAnalysis(state=ImpactAnalysisState.IN_TRIAGE),
        )]
        return bom

    def test_partner_view_redacts_identity_and_keeps_relationships(self) -> None:
        bom = self._make_bom()
        pair = make_bom_views(bom)

        for view_text in (pair.partner.json, pair.partner.xml):
            self.assertNotIn('internal-auth', view_text)
            self.assertNotIn('Corp Secrets Inc', view_text)
            self.assertNotIn('git.internal.example', view_text)
            self.assertNotIn('/srv/secret/auth.py', view_text)
            self.assertNotIn('pkg:pypi/internal-auth', view_text)

        for view in (pair.partner.json, pair.partner.xml):
            self.assertIn('restricted-component-1', view)
            self.assertIn('CVE-2026-0001', view)
            self.assertIn(RESTRICTED_COMPONENT_PROPERTY, view)

        # The internal view must still contain the raw markers.
        for view_text in (pair.internal.json, pair.internal.xml):
            self.assertIn('internal-auth', view_text)
            self.assertIn('Corp Secrets Inc', view_text)
            self.assertIn('https://git.internal.example/auth', view_text)
            self.assertIn('/srv/secret/auth.py', view_text)
            self.assertIn('pkg:pypi/internal-auth@1.0.0', view_text)
            self.assertNotIn('restricted-component-1', view_text)

    def test_relationships_survive_in_both_views(self) -> None:
        pair = make_bom_views(self._make_bom())
        self.assertTrue(pair.internal.relationship_report.is_complete)
        self.assertEqual(frozenset(('app', 'internal-auth', 'public-lib')),
                         pair.internal.relationship_report.component_refs)
        self.assertTrue(pair.partner.relationship_report.is_complete)
        self.assertEqual(frozenset(('app', 'restricted-component-1', 'public-lib')),
                         pair.partner.relationship_report.component_refs)
        self.assertEqual(frozenset((('app', 'restricted-component-1'),
                                    ('restricted-component-1', 'public-lib'))),
                         pair.partner.relationship_report.dependency_edges)
        self.assertEqual(frozenset((('CVE-2026-0001', frozenset(('restricted-component-1',))),)),
                         pair.partner.relationship_report.vulnerability_targets)

    def test_vulnerability_target_points_at_placeholder(self) -> None:
        pair = make_bom_views(self._make_bom())
        self.assertEqual({'internal-auth': 'restricted-component-1'}, dict(pair.restricted_bom_refs))

    def test_source_bom_is_not_modified(self) -> None:
        bom = self._make_bom()
        make_bom_views(bom)
        component = next(c for c in bom.components if c.bom_ref.value == 'internal-auth')
        self.assertEqual('internal-auth', component.name)
        self.assertEqual('https://git.internal.example/auth', str(component.external_references[0].url))

    def test_returns_named_placeholders_and_avoids_collisions(self) -> None:
        bom = self._make_bom()
        taken = Component(name='taken', bom_ref='restricted-component-1')
        bom.components.add(taken)
        pair = make_bom_views(bom)
        self.assertNotIn('restricted-component-1', pair.restricted_bom_refs.values())
        self.assertEqual('restricted-component-2', pair.restricted_bom_refs['internal-auth'])

    def test_custom_selector_and_sensitive_strings(self) -> None:
        pair = make_bom_views(self._make_bom(), restricted=['internal-auth'], sensitive_strings=['CVE-2026-0001'])
        self.assertNotIn('CVE-2026-0001', pair.partner.json)
        self.assertNotIn('CVE-2026-0001', pair.partner.xml)
        self.assertIn('CVE-2026-0001', pair.internal.json)

    def test_requires_at_least_one_restricted_component(self) -> None:
        bom = Bom(components=[Component(name='x', bom_ref='x')])
        with self.assertRaises(ValueError):
            make_bom_views(bom)

    def test_old_schema_rejected(self) -> None:
        bom = self._make_bom()
        with self.assertRaises(ValueError):
            make_bom_views(bom, schema_version=SchemaVersion.V1_3)

    def test_redactor_reusable(self) -> None:
        redactor = BomViewRedactor(self._make_bom())
        first = redactor.partner_view()
        second = redactor.partner_view()
        self.assertEqual(first.json, second.json)
        self.assertEqual(first.xml, second.xml)


class TestNestedRestrictedAssembly(TestCase):

    def test_nested_children_do_not_dangle(self) -> None:
        leaf = Component(name='internal-leaf', bom_ref='internal-leaf')
        restricted = _restricted('internal-assembly', 'internal-assembly', components=[leaf])
        public = Component(name='public', bom_ref='public')
        bom = Bom(components=[restricted, public])
        bom.dependencies = [
            Dependency(restricted.bom_ref, [Dependency(leaf.bom_ref), Dependency(public.bom_ref)]),
        ]
        bom.vulnerabilities = [Vulnerability(id='CVE-2', bom_ref='v2', affects=[BomTarget(ref='internal-leaf')])]
        pair = make_bom_views(bom)
        self.assertIn('internal-leaf', pair.restricted_bom_refs)
        self.assertNotIn('internal-leaf', [c.bom_ref.value for c in pair.partner.bom.components])
        self.assertTrue(pair.partner.relationship_report.is_complete)
        self.assertIn('restricted-component-1', pair.partner.json)


class TestMultipleRestrictedComponents(TestCase):

    def test_placeholders_are_distinct_and_stable(self) -> None:
        a = _restricted('same-name', 'a')
        b = _restricted('same-name', 'b')
        public = Component(name='pub', bom_ref='pub')
        bom = Bom(components=[a, b, public])
        bom.dependencies = [
            Dependency(a.bom_ref, [Dependency(public.bom_ref)]),
            Dependency(b.bom_ref, [Dependency(public.bom_ref)]),
        ]
        pair = make_bom_views(bom)
        self.assertEqual({'a': 'restricted-component-1', 'b': 'restricted-component-2'},
                         dict(pair.restricted_bom_refs))
        self.assertEqual(frozenset((('restricted-component-1', 'pub'), ('restricted-component-2', 'pub'))),
                         pair.partner.relationship_report.dependency_edges)
        # The shared name is not a discriminator; both placeholders must still be usable.
        self.assertEqual(2, len([c for c in pair.partner.bom.components if is_restricted_component(c)]))


class TestUriRedaction(TestCase):

    def test_redacted_repository_urls_stay_valid_uris(self) -> None:
        restricted = _restricted(
            'internal-repo',
            'internal-repo',
            external_references=[
                ExternalReference(type=ExternalReferenceType.VCS, url=XsUri('https://git.internal.example/repo')),
                ExternalReference(type=ExternalReferenceType.DISTRIBUTION,
                                  url=XsUri('https://artifacts.internal.example/repo.whl')),
            ],
        )
        public = Component(name='public', bom_ref='public')
        bom = Bom(components=[restricted, public])
        bom.dependencies = [Dependency(restricted.bom_ref, [Dependency(public.bom_ref)])]
        pair = make_bom_views(bom)
        parsed = Bom.from_json(json_loads(pair.partner.json))
        self.assertIsNotNone(parsed)
        placeholder = next(c for c in parsed.components if is_restricted_component(c))  # type: ignore[union-attr]
        self.assertFalse(placeholder.external_references)

    def test_sensitive_uri_inside_free_text_becomes_placeholder(self) -> None:
        restricted = _restricted(
            'internal-repo', 'internal-repo',
            description='see https://git.internal.example/repo for details',
        )
        bom = Bom(components=[restricted, Component(name='public', bom_ref='public')])
        bom.dependencies = [Dependency(restricted.bom_ref)]
        pair = make_bom_views(bom)
        self.assertNotIn('git.internal.example', pair.partner.json)


class TestVerificationHooks(TestCase):

    def test_raises_when_source_is_inconsistent(self) -> None:
        bom = Bom(components=[Component(name='x', bom_ref='x')])
        bom.dependencies = [Dependency(BomRef('missing'))]
        redactor = BomViewRedactor(bom, restricted=['x'])
        with self.assertRaises(BomReferenceIntegrityException):
            redactor.internal_view()

    def test_public_exceptions_are_exported(self) -> None:
        self.assertTrue(issubclass(BomReferenceIntegrityException, CycloneDxException))
        self.assertTrue(issubclass(BomIdentityLeakException, CycloneDxException))

    def test_data_model_name_collision_is_scoped(self) -> None:
        # The public view API may only rely on exceptions from the model module, not duplicate them.
        import cyclonedx.contrib.bom.views as views
        import cyclonedx.exception.model as model
        self.assertIs(model.BomReferenceIntegrityException, views.BomReferenceIntegrityException)
        self.assertIs(model.BomIdentityLeakException, views.BomIdentityLeakException)


class TestRootComponentHandling(TestCase):

    def test_root_component_listed_as_component_is_not_duplicated(self) -> None:
        root = Component(name='root', bom_ref='root', type=ComponentType.APPLICATION,
                         properties=[Property(name=RESTRICTED_COMPONENT_PROPERTY, value='true')])
        bom = Bom(components=[root])
        bom.metadata.component = root
        pair = make_bom_views(bom, restricted=['root'])
        self.assertTrue(pair.partner.relationship_report.is_complete)
        refs = [c.bom_ref.value for c in pair.partner.bom.components]
        refs += [pair.partner.bom.metadata.component.bom_ref.value]  # type: ignore[union-attr]
        self.assertEqual(['restricted-component-1'], refs)
