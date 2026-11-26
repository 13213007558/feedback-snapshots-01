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

"""
Export one BOM as an internal and a partner view.

The partner view replaces restricted components with stable placeholders while
keeping dependency edges and vulnerability targets intact. Both views are
re-parsed from JSON and XML and their relationship graphs are compared before
the example prints a summary.
"""

import sys
from io import StringIO
from json import loads as json_loads

from packageurl import PackageURL

from cyclonedx.contrib.bom.views import RESTRICTED_COMPONENT_PROPERTY, make_bom_views
from cyclonedx.model import ExternalReference, ExternalReferenceType, Property, XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.component_evidence import ComponentEvidence, Occurrence
from cyclonedx.model.contact import OrganizationalEntity
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.impact_analysis import ImpactAnalysisState
from cyclonedx.model.vulnerability import BomTarget, Vulnerability, VulnerabilityAnalysis

# region build the BOM

restricted = Component(
    name='internal-auth',
    group='corp',
    version='1.0.0',
    bom_ref='internal-auth',
    type=ComponentType.LIBRARY,
    purl=PackageURL(type='pypi', name='internal-auth', version='1.0.0'),
    supplier=OrganizationalEntity(name='Corp Secrets Inc'),
    evidence=ComponentEvidence(occurrences=[Occurrence(location='/srv/secret/auth.py')]),
    external_references=[ExternalReference(
        type=ExternalReferenceType.VCS,
        url=XsUri('https://git.internal.example/auth'),
    )],
    properties=[Property(name=RESTRICTED_COMPONENT_PROPERTY, value='true')],
)
public_lib = Component(name='public-lib', version='2.0.0', bom_ref='public-lib')
app = Component(name='app', bom_ref='app', type=ComponentType.APPLICATION)

bom = Bom(components=[restricted, public_lib])
bom.metadata.component = app
bom.dependencies = [
    Dependency(app.bom_ref, [Dependency(restricted.bom_ref, [Dependency(public_lib.bom_ref)])]),
    Dependency(public_lib.bom_ref),
]
bom.vulnerabilities = [Vulnerability(
    id='CVE-2026-0001',
    bom_ref='vuln-1',
    description='found in internal-auth at https://git.internal.example/auth',
    affects=[BomTarget(ref='internal-auth')],
    analysis=VulnerabilityAnalysis(state=ImpactAnalysisState.IN_TRIAGE),
)]

# endregion build the BOM

# region export and verify

pair = make_bom_views(bom)

for label, view in (('internal', pair.internal), ('partner', pair.partner)):
    for output_format, text in (('JSON', view.json), ('XML', view.xml)):
        # Re-parse to prove the document is self-consistent, not just a string.
        if output_format == 'JSON':
            Bom.from_json(json_loads(text))
        else:
            Bom.from_xml(StringIO(text))
        print(f'{label:8} {output_format}: parsed')
    print(f'{label:8} relationships: {view.relationship_report!r}')

if 'internal-auth' in pair.partner.json:
    print('ERROR: partner view leaked a restricted name', file=sys.stderr)
    sys.exit(2)
if 'internal-auth' not in pair.internal.json:
    print('ERROR: internal view lost the restricted name', file=sys.stderr)
    sys.exit(2)
print('restricted reference mapping (internal only):', dict(pair.restricted_bom_refs))

# endregion export and verify
