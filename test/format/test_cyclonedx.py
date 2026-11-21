import json
import xml.etree.ElementTree as ET

import pretend  # type: ignore
import pytest
from packaging.version import Version

import pip_audit._service as service
from pip_audit._format import CycloneDxFormat


@pytest.fixture
def mixed_public_internal_data(vuln_data):
    """
    A result set mixing public dependencies with an internally-installed
    placeholder dependency, mimicking an audit of a private environment.
    """
    internal_dep = service.ResolvedDependency(name="internal-placeholder", version=Version("0.0.1"))
    return {
        **vuln_data,
        internal_dep: [
            service.VulnerabilityResult(
                id="VULN-INTERNAL-0",
                description="A vulnerability in an internal package",
                fix_versions=[Version("0.0.2")],
                aliases=set(),
            )
        ],
    }


@pytest.mark.parametrize(
    "inner", [CycloneDxFormat.InnerFormat.Xml, CycloneDxFormat.InnerFormat.Json]
)
def test_cyclonedx_manifest(inner):
    fmt = CycloneDxFormat(inner_format=inner)
    assert fmt.is_manifest


def test_cyclonedx_inner_json(vuln_data):
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)

    # We don't test CycloneDX's formatting/layout decisions, only that
    # the formatter emits correct JSON when initialized in JSON mode.
    assert json.loads(formatter.format(vuln_data, [])) is not None


def test_cyclonedx_inner_xml(vuln_data):
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Xml)

    # We don't test CycloneDX's formatting/layout decisions, only that
    # the formatter emits correct XML when initialized in XML mode.
    assert ET.fromstring(formatter.format(vuln_data, [])) is not None


def test_cyclonedx_skipped_dep(vuln_data_skipped_dep):
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)

    # Just test that a skipped dependency doesn't cause the formatter to blow up
    output = formatter.format(vuln_data_skipped_dep, [])
    data = json.loads(output)
    assert data is not None

    # A skipped dependency is omitted from the BOM entirely: it must not
    # appear as a component, and its skip reason must not leak into the output.
    component_names = [comp["name"] for comp in data.get("components", [])]
    assert "bar" not in component_names
    assert "skip-reason" not in output


def test_cyclonedx_fix(monkeypatch, vuln_data, fix_data):
    import pip_audit._format.cyclonedx as cyclonedx

    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(cyclonedx, "logger", logger)

    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)
    assert json.loads(formatter.format(vuln_data, fix_data)) is not None

    # The CycloneDX format doesn't support fixes so we expect to log a warning
    assert len(logger.warning.calls) == 1


def test_cyclonedx_vulnerabilities_linked_to_components(vuln_data):
    """
    Backstop test to ensure vulnerabilities are correctly linked to their components.

    This test verifies that the CycloneDX output properly links vulnerabilities
    to components via the 'affects' field. If the cyclonedx-python-lib library
    changes its API in a future version, this test will fail and provide advance
    warning of breaking changes.
    """
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)
    output = formatter.format(vuln_data, [])
    data = json.loads(output)

    # Build a mapping of component names to their bom-refs
    component_bomrefs = {comp["name"]: comp["bom-ref"] for comp in data.get("components", [])}

    # Verify we have components and vulnerabilities in the output
    assert len(component_bomrefs) > 0, "Should have components in CycloneDX output"
    assert (
        len(data.get("vulnerabilities", [])) > 0
    ), "Should have vulnerabilities in CycloneDX output"

    # Track which components have vulnerabilities linked to them
    components_with_vulns = set()

    # Check each vulnerability has proper 'affects' linking
    for vuln in data["vulnerabilities"]:
        affects = vuln.get("affects", [])

        # Each vulnerability should have at least one affected component
        assert len(affects) > 0, f"Vulnerability {vuln.get('id')} should have 'affects' field"

        for affected in affects:
            # Each affected entry should have a 'ref' field
            assert "ref" in affected, f"Vulnerability {vuln.get('id')} affects entry missing 'ref'"

            vuln_ref = affected["ref"]

            # The ref should not be empty
            assert vuln_ref, f"Vulnerability {vuln.get('id')} has empty 'ref' in affects"

            # The ref should match one of the component bom-refs
            assert (
                vuln_ref in component_bomrefs.values()
            ), f"Vulnerability {vuln.get('id')} references unknown bom-ref: {vuln_ref}"

            # Track that this component has a vulnerability linked to it
            for comp_name, comp_ref in component_bomrefs.items():
                if comp_ref == vuln_ref:
                    components_with_vulns.add(comp_name)

    # Verify that components with vulnerabilities in vuln_data have them linked in output
    # (This ensures the linking is actually working, not just present but wrong)
    for dep, vulns in vuln_data.items():
        if vulns:  # If this dependency has vulnerabilities
            assert (
                dep.name in components_with_vulns
            ), f"Component {dep.name} has vulnerabilities but they're not properly linked"


def test_cyclonedx_is_usable_bom(vuln_data):
    """
    The JSON output must be a well-formed CycloneDX BOM that an external
    reviewer can consume: standard envelope fields plus components and
    vulnerabilities.
    """
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)
    data = json.loads(formatter.format(vuln_data, []))

    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.4"
    assert data["version"] == 1
    assert data["serialNumber"].startswith("urn:uuid:")
    assert isinstance(data["components"], list)
    assert len(data["components"]) > 0


def test_cyclonedx_components_carry_version_and_risk_info(mixed_public_internal_data):
    """
    Every component (public or internal) must carry its name and resolved
    version, and every vulnerability must carry its identifier and
    description, so an external reviewer gets version and risk information.
    """
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)
    data = json.loads(formatter.format(mixed_public_internal_data, []))

    components_by_name = {comp["name"]: comp for comp in data["components"]}
    for dep, vulns in mixed_public_internal_data.items():
        assert dep.name in components_by_name
        assert components_by_name[dep.name]["version"] == str(dep.version)

        for vuln in vulns:
            matches = [v for v in data["vulnerabilities"] if v["id"] == vuln.id]
            assert len(matches) == 1
            assert matches[0]["description"] == vuln.description


def test_cyclonedx_only_discloses_authorized_source_info(mixed_public_internal_data):
    """
    The BOM is shared with external reviewers who may see component
    versions and risk information, but not local paths or build source
    addresses. Components must only contain identity fields, and the
    serialized output must not contain file URLs, local paths, or
    external references.
    """
    for inner in (CycloneDxFormat.InnerFormat.Json, CycloneDxFormat.InnerFormat.Xml):
        formatter = CycloneDxFormat(inner_format=inner)
        output = formatter.format(mixed_public_internal_data, [])

        assert "file:" not in output
        assert "externalReference" not in output

    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)
    data = json.loads(formatter.format(mixed_public_internal_data, []))
    for comp in data["components"]:
        # Only identity fields are authorized for disclosure: no purl,
        # no hashes, no external references, nothing path-like.
        assert set(comp.keys()) <= {"bom-ref", "name", "type", "version"}
        assert not comp["bom-ref"].startswith("pkg:")


def test_cyclonedx_no_vuln_data(no_vuln_data):
    """
    With no vulnerabilities found, the output is still a usable BOM:
    all components are present with their versions, and there are no
    vulnerability entries.
    """
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)
    data = json.loads(formatter.format(no_vuln_data, []))

    assert data["bomFormat"] == "CycloneDX"
    components_by_name = {comp["name"]: comp for comp in data["components"]}
    assert set(components_by_name) == {"foo", "bar"}
    for dep in no_vuln_data:
        assert components_by_name[dep.name]["version"] == str(dep.version)
    assert not data.get("vulnerabilities")


def test_cyclonedx_no_vuln_data_skipped_dep(no_vuln_data_skipped_dep):
    """
    With no vulnerabilities and a skipped dependency, the BOM contains
    only the resolved components; the skipped dependency is omitted.
    """
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)
    data = json.loads(formatter.format(no_vuln_data_skipped_dep, []))

    component_names = [comp["name"] for comp in data["components"]]
    assert sorted(component_names) == ["bar", "foo"]
    assert not data.get("vulnerabilities")
