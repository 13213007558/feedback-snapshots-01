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

from __future__ import annotations

import json
from unittest import TestCase
from xml.etree import ElementTree

from cyclonedx.model import Copyright
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.component_evidence import ComponentEvidence, Occurrence
from cyclonedx.output import ExportPolicy, OutputFormat, SchemaVersion, export_bom, make_outputter

SCHEMA_VERSION = SchemaVersion.V1_7
SYNTHETIC_MARKER = 'SYNTHETIC-EVIDENCE-MARKER-7558-191'
SECRET_PATH = 'build-artifacts/private/scanner-secret.txt'
XML_NS = 'http://cyclonedx.org/schema/bom/1.7'


class SharedEvidenceClassificationTest(TestCase):

    def setUp(self) -> None:
        self.evidence = ComponentEvidence(
            copyright=[Copyright(text=SYNTHETIC_MARKER)],
            occurrences=[Occurrence(location=SECRET_PATH)],
        )
        self.source = Component(
            bom_ref='source-scan',
            type=ComponentType.LIBRARY,
            name='source-scanner-result',
            evidence=self.evidence,
        )
        self.artifact = Component(
            bom_ref='artifact-scan',
            type=ComponentType.LIBRARY,
            name='artifact-scanner-result',
            evidence=self.evidence,
        )
        self.bom = Bom(components=[self.source, self.artifact])
        self.bom.register_dependency(self.source, [self.artifact])
        self.policy = ExportPolicy(
            component_levels={
                self.source: 'internal',
                self.artifact: 'public',
            },
            field_levels={
                'copyright': 'public',
                'occurrences': 'internal',
            },
        )
        self.public_policy = self.policy.for_outlet('public')
        self.internal_policy = self.policy.for_outlet('internal')

    def _component_json(self, document: str, bom_ref: str) -> dict:
        bom_json = json.loads(document)
        components = {component['bom-ref']: component for component in bom_json['components']}
        self.assertIn(bom_ref, components)
        return components[bom_ref]

    def _component_xml(self, document: str, bom_ref: str) -> ElementTree.Element:
        root = ElementTree.fromstring(document)
        namespaces = {'c': XML_NS}
        components = {
            component.attrib['bom-ref']: component
            for component in root.findall('.//c:component', namespaces)
        }
        self.assertIn(bom_ref, components)
        return components[bom_ref]

    def _assert_public_component(self, component: dict | ElementTree.Element, xml: bool = False) -> None:
        if xml:
            namespaces = {'c': XML_NS}
            text = ElementTree.tostring(component, encoding='unicode')
            self.assertIn(SYNTHETIC_MARKER, text)
            self.assertNotIn(SECRET_PATH, text)
            evidence = component.find('c:evidence', namespaces)
            self.assertIsNotNone(evidence)
            self.assertEqual([], evidence.findall('.//c:occurrence', namespaces))
            self.assertEqual(1, len(evidence.findall('.//c:text', namespaces)))
        else:
            evidence = component['evidence']
            self.assertEqual(SYNTHETIC_MARKER, evidence['copyright'][0]['text'])
            self.assertNotIn('occurrences', evidence)
            self.assertNotIn(SECRET_PATH, json.dumps(component))

    def _assert_internal_high_component(self, component: dict | ElementTree.Element, xml: bool = False) -> None:
        text = ElementTree.tostring(component, encoding='unicode') if xml else json.dumps(component)
        self.assertIn(SYNTHETIC_MARKER, text)
        self.assertIn(SECRET_PATH, text)
        if xml:
            namespaces = {'c': XML_NS}
            evidence = component.find('c:evidence', namespaces)
            self.assertIsNotNone(evidence)
            self.assertEqual(SECRET_PATH, evidence.find('.//c:location', namespaces).text)
        else:
            self.assertEqual(SECRET_PATH, component['evidence']['occurrences'][0]['location'])

    def _assert_relationships_json(self, document: str) -> None:
        dependencies = {d['ref']: d for d in json.loads(document)['dependencies']}
        self.assertIn('source-scan', dependencies)
        self.assertIn('artifact-scan', dependencies)
        child_refs = set(dependencies['source-scan'].get('dependsOn', []))
        self.assertEqual({'artifact-scan'}, child_refs)

    def _assert_relationships_xml(self, document: str) -> None:
        root = ElementTree.fromstring(document)
        namespaces = {'c': XML_NS}
        dependencies = {d.attrib['ref']: d for d in root.findall('.//c:dependency', namespaces)}
        self.assertIn('source-scan', dependencies)
        self.assertIn('artifact-scan', dependencies)
        child_refs = {
            child.attrib['ref']
            for child in dependencies['source-scan'].findall('c:dependency', namespaces)
        }
        self.assertEqual({'artifact-scan'}, child_refs)

    def _assert_original_unchanged(self) -> None:
        self.assertIs(self.source.evidence, self.evidence)
        self.assertIs(self.artifact.evidence, self.evidence)
        self.assertEqual(SYNTHETIC_MARKER, next(iter(self.evidence.copyright)).text)
        self.assertEqual(SECRET_PATH, next(iter(self.evidence.occurrences)).location)
        self.assertEqual(1, len(self.evidence.copyright))
        self.assertEqual(1, len(self.evidence.occurrences))

    def test_shared_evidence_is_projected_per_reference_in_required_order(self) -> None:
        public_json = export_bom(
            self.bom, OutputFormat.JSON, SCHEMA_VERSION, policy=self.public_policy)
        internal_xml = export_bom(
            self.bom, OutputFormat.XML, SCHEMA_VERSION, policy=self.internal_policy)

        self._assert_public_component(self._component_json(public_json, 'source-scan'))
        self._assert_public_component(self._component_json(public_json, 'artifact-scan'))
        self._assert_relationships_json(public_json)
        self.assertNotIn(SECRET_PATH, public_json)

        source_xml = self._component_xml(internal_xml, 'source-scan')
        artifact_xml = self._component_xml(internal_xml, 'artifact-scan')
        self._assert_internal_high_component(source_xml, xml=True)
        self._assert_public_component(artifact_xml, xml=True)
        self._assert_relationships_xml(internal_xml)

        # Reverse outlet/format order and exercise both formats for each outlet.
        internal_json = export_bom(
            self.bom, OutputFormat.JSON, SCHEMA_VERSION, policy=self.internal_policy)
        public_xml = export_bom(
            self.bom, OutputFormat.XML, SCHEMA_VERSION, policy=self.public_policy)

        source_json = self._component_json(internal_json, 'source-scan')
        artifact_json = self._component_json(internal_json, 'artifact-scan')
        self._assert_internal_high_component(source_json)
        self._assert_public_component(artifact_json)
        self._assert_relationships_json(internal_json)

        self._assert_public_component(self._component_xml(public_xml, 'source-scan'), xml=True)
        self._assert_public_component(self._component_xml(public_xml, 'artifact-scan'), xml=True)
        self._assert_relationships_xml(public_xml)
        self.assertNotIn(SECRET_PATH, public_xml)

        # Repeating the first order must not inherit internal fields.
        repeated_public_json = export_bom(
            self.bom, OutputFormat.JSON, SCHEMA_VERSION, policy=ExportPolicy.public(
                component_levels={self.source: 'internal', self.artifact: 'public'},
                field_levels={'copyright': 'public', 'occurrences': 'internal'},
            ))
        self.assertEqual(public_json, repeated_public_json)
        repeated_public_xml = export_bom(
            self.bom, OutputFormat.XML, SCHEMA_VERSION, policy=self.public_policy)
        self.assertEqual(public_xml, repeated_public_xml)
        self._assert_original_unchanged()

    def test_same_outputter_can_switch_between_full_public_and_internal_output(self) -> None:
        outputter = make_outputter(self.bom, OutputFormat.JSON, SCHEMA_VERSION)
        public_json = outputter.output_as_string(policy=self.public_policy)
        full_json = outputter.output_as_string()
        internal_json = outputter.output_as_string(policy=self.internal_policy)
        public_again = outputter.output_as_string(outlet='public', **{
            'component_levels': {self.source: 'internal', self.artifact: 'public'},
            'field_levels': {'copyright': 'public', 'occurrences': 'internal'},
        })

        self.assertNotIn(SECRET_PATH, public_json)
        self.assertIn(SECRET_PATH, full_json)
        self.assertIn(SECRET_PATH, internal_json)
        self.assertNotIn(SECRET_PATH, public_again)
        self.assertEqual(public_json, public_again)
        self._assert_original_unchanged()

    def test_constructor_labels_and_exporter_facade(self) -> None:
        evidence = ComponentEvidence(
            copyright=[Copyright(text=SYNTHETIC_MARKER)],
            occurrences=[Occurrence(location=SECRET_PATH)],
            field_levels={'copyright': 'public', 'occurrences': 'internal'},
        )
        source = Component(
            name='source', bom_ref='source', release_level='internal', evidence=evidence)
        artifact = Component(
            name='artifact', bom_ref='artifact', release_level='public', evidence=evidence)
        bom = Bom(components=[source, artifact])

        from cyclonedx.output.classification import LeveledExporter

        exporter = LeveledExporter(bom, schema_version=SCHEMA_VERSION)
        public_json = exporter.public_json()
        internal_xml = exporter.internal_xml()

        self.assertIn(SYNTHETIC_MARKER, public_json)
        self.assertNotIn(SECRET_PATH, public_json)
        source_xml = self._component_xml(internal_xml, 'source')
        artifact_xml = self._component_xml(internal_xml, 'artifact')
        self._assert_internal_high_component(source_xml, xml=True)
        self._assert_public_component(artifact_xml, xml=True)
        self.assertIs(source.evidence, evidence)
        self.assertIs(artifact.evidence, evidence)

    def test_default_full_manifest_still_contains_shared_evidence(self) -> None:
        full_json = make_outputter(self.bom, OutputFormat.JSON, SCHEMA_VERSION).output_as_string()
        full_xml = make_outputter(self.bom, OutputFormat.XML, SCHEMA_VERSION).output_as_string()
        self.assertIn(SYNTHETIC_MARKER, full_json)
        self.assertIn(SECRET_PATH, full_json)
        self.assertIn(SYNTHETIC_MARKER, full_xml)
        self.assertIn(SECRET_PATH, full_xml)
        self._assert_original_unchanged()
