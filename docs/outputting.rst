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

Outputting
==========

Once you have an instance of a :py:mod:`cyclonedx.model.bom.Bom` you can produce output in either **JSON** or **XML**
against any of the supported CycloneDX schema versions.

We provide two helper methods:

* Output to string (for you to do with as you require)
* Output directly to a filename you provide

By default output will be in XML at latest supported schema version - see :py:mod:`cyclonedx.output.LATEST_SUPPORTED_SCHEMA_VERSION`.

Supported CycloneDX Schema Versions
-----------------------------------

This library supports the following schema versions:

* 1.7 (XML, JSON) - the latest supported schema version
* 1.6 (XML, JSON)
* 1.5 (XML, JSON)
* 1.4 (XML, JSON)
* 1.3 (XML, JSON)
* 1.2 (XML, JSON)
* 1.0 (XML) - `(note, 1.1 schema version has no support for JSON)`
* 1.1 (XML) - `(note, 1.1 schema version has no support for JSON)`

Outputting to JSON
------------------

The below example relies on the latest schema version, but sets the output format to JSON. Output is returned
as a ``str``.

.. code-block:: python

    from cyclonedx.output import make_outputter, BaseOutput, OutputFormat, SchemaVersion

    outputter: BaseOutput = make_outputter(bom=bom, output_format=OutputFormat.JSON, schema_version=SchemaVersion.V1_7)
    bom_json: str = outputter.output_as_string()

Alternatively, if the output format and schema version are constants, you can use the predefined format+schema combined outputs:

.. code-block:: python

    from cyclonedx.output.json import JsonV1Dot7

    outputter = JsonV1Dot7(bom=bom)
    bom_json: str = outputter.output_as_string()


Outputting to XML
------------------

The below example relies on the default output format being XML, but overrides the schema version to 1.2. Output is
written to the supplied filename.

.. code-block:: python

    from cyclonedx.output import make_outputter, BaseOutput, OutputFormat, SchemaVersion

    outputter: BaseOutput = make_outputter(bom=bom, output_format=OutputFormat.XML, schema_version=SchemaVersion.V1_2)
    outputter.output_to_file(filename='/tmp/sbom-v1.2.xml')

Alternatively, if the output format and schema version are constants, you can use the predefined format+schema combined outputs:

.. code-block:: python

    from cyclonedx.output.xml import XmlV1Dot2

    outputter = XmlV1Dot2(bom=bom)
    outputter.output_to_file(filename='/tmp/sbom-v1.2.xml')

Leveled And Reference-Aware Exports
-----------------------------------

Source and artifact scans can assign the same ``ComponentEvidence`` instance to
multiple components.  Use :class:`cyclonedx.output.ExportPolicy` to label
evidence fields and component reference clearance.  The exporter deep-copies the
BOM and creates a separate evidence projection for every component reference; the
original BOM and shared evidence object are never modified.

Fields without an explicit label use ``default_field_level`` (``INTERNAL`` by
default), so a public outlet only emits explicitly public material unless a
less conservative default is supplied.

.. code-block:: python

    from cyclonedx.model import Copyright
    from cyclonedx.model.component_evidence import ComponentEvidence, Occurrence
    from cyclonedx.output import ExportPolicy, OutputFormat, SchemaVersion, export_bom

    evidence = ComponentEvidence(
        copyright=[Copyright(text='synthetic marker')],
        occurrences=[Occurrence(location='private/build/path')],
    )
    # source_component.evidence = evidence
    # artifact_component.evidence = evidence

    policy = ExportPolicy(
        component_levels={'source-bom-ref': 'internal', 'artifact-bom-ref': 'public'},
        field_levels={'copyright': 'public', 'occurrences': 'internal'},
    )

    public_json = export_bom(
        bom, OutputFormat.JSON, SchemaVersion.V1_7, policy=policy.for_outlet('public')
    )
    internal_xml = export_bom(
        bom, OutputFormat.XML, SchemaVersion.V1_7, policy=policy.for_outlet('internal')
    )

Calling the existing outputters without a policy, or using
``ExportPolicy.full()``, keeps the complete manifest behavior.  Policies can be
passed to :func:`cyclonedx.output.make_outputter` or to an outputter's
``output_as_string(policy=...)`` method, allowing public and internal exports to
be generated in any order.
