"""Offline contract tests for shareable response diagnostics.

The tests generate their own certificate material and metadata, so they never
depend on network access or fixture XML checked into the repository.  Each
check consumes one locally signed AuthnResponse and asserts on the structured
diagnostic that would be attached to a federation login ticket.
"""

import json

import pytest

from diagnostics_helpers import PRIVACY_MARKERS
from diagnostics_helpers import SyntheticFederation
from saml2.diagnostics import APPROVED_REQUEST_FIELDS
from saml2.diagnostics import APPROVED_STAGE_FIELDS
from saml2.diagnostics import APPROVED_TRUST_FIELDS
from saml2.diagnostics import ResponseDiagnostics
from saml2.diagnostics import describe_trust_materials
from saml2.response import authn_response
from saml2.sigver import SignatureError


EVIDENCE_STAGES = [
    "request_binding",
    "response_validation",
    "signature_verification",
    "assertion_selection",
    "attribute_mapping",
    "identity_issuance",
]


@pytest.fixture(scope="module")
def federation(tmp_path_factory):
    workdir = tmp_path_factory.mktemp("response-diagnostics")
    federation = SyntheticFederation(str(workdir))

    cert_v1, key_v1 = federation.generate_certificate("idp-trust-v1")
    cert_v2, key_v2 = federation.generate_certificate("idp-trust-v2")
    federation.generate_certificate("sp")

    metadata_v1 = federation.metadata_for(cert_v1, "idp-trust-v1.xml")
    metadata_v2 = federation.metadata_for(cert_v2, "idp-trust-v2.xml")
    sp_metadata = federation.sp_metadata()
    mapping_failure_maps = federation.attribute_map_missing_principal_name()

    return {
        "workdir": str(workdir),
        "federation": federation,
        "cert_v1": cert_v1,
        "key_v1": key_v1,
        "cert_v2": cert_v2,
        "key_v2": key_v2,
        "metadata_v1": metadata_v1,
        "metadata_v2": metadata_v2,
        "sp_metadata": sp_metadata,
        "mapping_failure_maps": mapping_failure_maps,
    }


def _process(fixture_data, response_xml, request_id, metadata_path, attribute_map_dir=None):
    federation = fixture_data["federation"]
    config = federation.sp_config(metadata_path, attribute_map_dir=attribute_map_dir)
    diagnostics = ResponseDiagnostics(request_id=request_id)
    response = authn_response(
        config,
        ["https://sp.privacy.example/acs"],
        outstanding_queries={request_id: "https://sp.privacy.example/sso"},
        timeslack=300,
        diagnostics=diagnostics,
    )
    response.loads(response_xml, decode=False)
    return response


APPROVED_TOP_LEVEL_FIELDS = {
    "schema",
    "request",
    "trust_materials",
    "stages",
    "failure_stage",
    "outcome",
    "identity_published",
}


def _assert_shareable(payload):
    assert set(payload) == APPROVED_TOP_LEVEL_FIELDS
    assert payload["schema"] == "pysaml2-response-diagnostics/1"
    assert set(payload["request"]) <= APPROVED_REQUEST_FIELDS

    assert isinstance(payload["trust_materials"], list)
    for material in payload["trust_materials"]:
        assert set(material) == APPROVED_TRUST_FIELDS
        assert material["version"] and material["version"].startswith("sha256:")
        assert material["used"] is True

    for stage in payload["stages"]:
        assert stage["stage"] in EVIDENCE_STAGES
        assert set(stage) <= APPROVED_STAGE_FIELDS[stage["stage"]] | {"stage", "outcome"}
        assert stage["outcome"] in {"passed", "failed", "skipped"}
        assert stage["request_bound"] is True

    serialized = json.dumps(payload)
    for marker in PRIVACY_MARKERS:
        assert marker not in serialized


def test_mapping_failure_keeps_earlier_shareable_evidence(federation):
    response_xml = federation["federation"].authn_response(
        federation["federation"].idp_server(
            federation["cert_v1"], federation["key_v1"], federation["sp_metadata"]
        ),
        "request-mapping-failure",
    )

    # The raw response necessarily contains the synthetic identity markers;
    # proving them absent from the diagnostic below is therefore meaningful.
    for marker in ("PRIVACY-MARKER-NAMEID", "PRIVACY-MARKER-VALUE", "privacy-marker@example.invalid"):
        assert marker in response_xml

    response = _process(
        federation,
        response_xml,
        "request-mapping-failure",
        federation["metadata_v1"],
        attribute_map_dir=federation["mapping_failure_maps"],
    )
    response.verify()

    # Trust material v1 verified the signature, so the response passed the
    # signature and assertion stages even though identity mapping dropped an
    # attribute and therefore no identity was published.
    payload = response.diagnostics.to_dict()
    _assert_shareable(payload)

    assert [stage["stage"] for stage in payload["stages"]] == [
        "request_binding",
        "signature_verification",
        "response_validation",
        "assertion_selection",
        "attribute_mapping",
        "identity_issuance",
    ]
    assert payload["failure_stage"] == "attribute_mapping"
    assert payload["identity_published"] is False
    assert payload["outcome"] == "failed"

    signature_stage = payload["stages"][1]
    assert signature_stage["outcome"] == "passed"
    assert signature_stage["verified"] is True
    assert signature_stage["trust_material_version"] == payload["trust_materials"][0]["version"]

    mapping_stage = payload["stages"][4]
    assert mapping_stage["outcome"] == "failed"
    assert mapping_stage["asserted_attribute_count"] == 2
    assert mapping_stage["mapped_attribute_count"] == 1
    assert mapping_stage["unmapped_attribute_count"] == 1

    issuance_stage = payload["stages"][-1]
    assert issuance_stage["stage"] == "identity_issuance"
    assert issuance_stage["published"] is False
    assert payload["stages"][2]["stage"] == "response_validation"
    assert payload["stages"][2]["outcome"] == "passed"

    ticket = response.diagnostics.to_ticket()
    assert ticket == response.diagnostics.to_json()
    assert json.loads(ticket) == payload
    for marker in PRIVACY_MARKERS:
        assert marker not in ticket
        assert marker not in repr(response.diagnostics)


def test_trust_material_change_and_full_success_publishes_identity(federation):
    response_xml = federation["federation"].authn_response(
        federation["federation"].idp_server(
            federation["cert_v2"], federation["key_v2"], federation["sp_metadata"]
        ),
        "request-full-success",
    )

    response = _process(federation, response_xml, "request-full-success", federation["metadata_v2"])
    response.verify()

    payload = response.diagnostics.to_dict()
    _assert_shareable(payload)

    assert payload["failure_stage"] is None
    assert payload["identity_published"] is True
    assert payload["outcome"] == "succeeded"

    assert len(payload["trust_materials"]) == 1
    material = payload["trust_materials"][0]
    assert material["source"] == "idp-trust-v2.xml"
    assert material["used"] is True

    signature_stage = next(stage for stage in payload["stages"] if stage["stage"] == "signature_verification")
    assert signature_stage["outcome"] == "passed"
    assert signature_stage["trust_material_version"] == material["version"]
    assert signature_stage["certificate_sha256"] == material["certificate_sha256"]

    mapping_stage = next(stage for stage in payload["stages"] if stage["stage"] == "attribute_mapping")
    assert mapping_stage["outcome"] == "passed"
    assert mapping_stage["asserted_attribute_count"] == mapping_stage["mapped_attribute_count"] == 2

    issuance_stage = payload["stages"][-1]
    assert issuance_stage["stage"] == "identity_issuance"
    assert issuance_stage["published"] is True


def test_trust_material_versions_differ_across_the_two_checks(federation):
    first = _process(
        federation,
        federation["federation"].authn_response(
            federation["federation"].idp_server(federation["cert_v1"], federation["key_v1"], federation["sp_metadata"]),
            "request-version-v1",
        ),
        "request-version-v1",
        federation["metadata_v1"],
    )
    first.verify()

    second = _process(
        federation,
        federation["federation"].authn_response(
            federation["federation"].idp_server(federation["cert_v2"], federation["key_v2"], federation["sp_metadata"]),
            "request-version-v2",
        ),
        "request-version-v2",
        federation["metadata_v2"],
    )
    second.verify()

    first_material = first.diagnostics.to_dict()["trust_materials"][0]
    second_material = second.diagnostics.to_dict()["trust_materials"][0]
    assert first_material["issuer_display"] == second_material["issuer_display"]
    assert first_material["version"] != second_material["version"]
    assert first_material["certificate_sha256"] != second_material["certificate_sha256"]


def test_unrelated_request_id_is_not_bound_to_the_diagnostic(federation):
    response_xml = federation["federation"].authn_response(
        federation["federation"].idp_server(federation["cert_v2"], federation["key_v2"], federation["sp_metadata"]),
        "request-other",
    )
    config = federation["federation"].sp_config(federation["metadata_v2"])
    diagnostics = ResponseDiagnostics(request_id="request-expected")
    response = authn_response(
        config,
        ["https://sp.privacy.example/acs"],
        outstanding_queries={"request-other": "https://sp.privacy.example/sso"},
        timeslack=300,
        diagnostics=diagnostics,
    )
    response.loads(response_xml, decode=False)

    payload = response.diagnostics.to_dict()
    assert payload["request"]["request_bound"] is False
    binding_stage = payload["stages"][0]
    assert binding_stage["stage"] == "request_binding"
    assert binding_stage["outcome"] == "failed"


def test_signature_failure_stops_before_identity_is_published(federation):
    response_xml = federation["federation"].authn_response(
        federation["federation"].idp_server(federation["cert_v2"], federation["key_v2"], federation["sp_metadata"]),
        "request-bad-metadata",
    )

    with pytest.raises(SignatureError):
        _process(federation, response_xml, "request-bad-metadata", federation["metadata_v1"])

    diagnostics = ResponseDiagnostics(request_id="request-bad-metadata")
    config = federation["federation"].sp_config(federation["metadata_v1"])
    response = authn_response(
        config,
        ["https://sp.privacy.example/acs"],
        outstanding_queries={"request-bad-metadata": "https://sp.privacy.example/sso"},
        timeslack=300,
        diagnostics=diagnostics,
    )
    with pytest.raises(SignatureError):
        response.loads(response_xml, decode=False)

    payload = diagnostics.to_dict()
    signature_stage = next(stage for stage in payload["stages"] if stage["stage"] == "signature_verification")
    assert signature_stage["outcome"] == "failed"
    assert payload["failure_stage"] == "signature_verification"
    assert payload["identity_published"] is False


def test_trust_material_description_is_scoped_to_the_displayed_issuer(federation):
    config = federation["federation"].sp_config(federation["metadata_v1"])
    metadata = config.metadata

    described = describe_trust_materials(metadata, "https://idp.privacy.example/metadata")
    assert described
    assert all(item["issuer_display"] == "https://idp.privacy.example/metadata" for item in described)
    assert all(item["used"] is False for item in described)

    assert describe_trust_materials(metadata, "https://unknown.example/metadata") == []


def test_serialization_allow_list_drops_injected_raw_fields():
    diagnostics = ResponseDiagnostics("request-injected")
    diagnostics._request["raw_response_xml"] = "<samlp:Response>PRIVACY-MARKER-RAW-XML</samlp:Response>"
    diagnostics._request["issuer_display"] = "<saml:Issuer>PRIVACY-MARKER-RAW-XML</saml:Issuer>"
    diagnostics._trust_materials.append(
        {
            "source": "idp.xml",
            "version": "sha256:abc",
            "issuer_display": "https://idp.example/metadata",
            "used": True,
            "certificate_sha256": "abc",
            "saml_attribute": "PRIVACY-MARKER-VALUE",
        }
    )
    diagnostics._stages.append(
        {
            "stage": "attribute_mapping",
            "outcome": "failed",
            "request_id": "request-injected",
            "request_bound": True,
            "asserted_attribute_count": 1,
            "mapped_attribute_count": 0,
            "raw_attribute": "PRIVACY-MARKER-VALUE",
        }
    )
    diagnostics._stages.append(
        {
            "stage": "signature_verification",
            "outcome": "passed",
            "request_bound": True,
            "verified": True,
            "saml_response": "<samlp:Response>PRIVACY-MARKER-RAW-XML</samlp:Response>",
        }
    )

    payload = diagnostics.to_dict()
    assert "raw_response_xml" not in payload["request"]
    assert payload["request"]["issuer_display"] is None
    assert set(payload["trust_materials"][0]) == APPROVED_TRUST_FIELDS
    assert set(payload["stages"][0]) <= APPROVED_STAGE_FIELDS["attribute_mapping"] | {"stage", "outcome"}
    assert "raw_attribute" not in payload["stages"][0]

    serialized = diagnostics.to_json()
    for marker in PRIVACY_MARKERS:
        assert marker not in serialized
