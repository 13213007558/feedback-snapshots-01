import pytest

import identity
import resolver


def test_declared_view_makes_no_file_lookup(fixture_paths):
    declared = resolver.declared_view(str(fixture_paths["host"]))
    assert len(declared["assembly_refs"]) == 2
    assert declared["assembly_refs"][0]["declared"]["key_kind"] == "token"
    assert declared["assembly_refs"][1]["declared"]["key_kind"] == "full_key"
    assert declared["assembly_refs"][1]["declared"]["retargetable"] is True
    assert declared["layer" if "layer" in declared else "host"]


def test_nested_typeref_chain_reaches_assembly_ref(fixture_paths):
    declared = resolver.declared_view(str(fixture_paths["host"]))
    by_rid = {item["rid"]: item for item in declared["typename_resolution"]}
    nested = by_rid[3]
    assert nested["display"] == "Contoso.Utils.Facade+Builder"
    assert nested["anchor_assembly_ref"] == 1
    assert [part["level"] for part in nested["chain"]] == ["type", "type", "assembly_ref"]


def test_module_scoped_typeref_has_no_assembly_anchor(fixture_paths):
    declared = resolver.declared_view(str(fixture_paths["host"]))
    system_object = declared["typename_resolution"][0]
    assert system_object["status"] == "no_assembly_anchor"
    assert system_object["anchor_assembly_ref"] is None


def _resolve(paths, policy):
    return resolver.resolve(
        str(paths["host"]),
        [str(paths["candidate_v1"]), str(paths["candidate_v2"])],
        policy,
    )


def test_exact_identity_separates_the_two_dependencies(fixture_paths):
    report = _resolve(fixture_paths, "exact_identity")
    selected = {ref["assembly_ref_rid"]: ref["selected"]["path"] for ref in report["assembly_refs"]}
    assert selected[1].endswith("v1/Contoso.Utils.dll")
    assert selected[2].endswith("v2/Contoso.Utils.dll")


def test_name_only_policy_collapses_both_refs_onto_one_file(fixture_paths):
    report = _resolve(fixture_paths, "name_only_highest_version")
    selected = {ref["assembly_ref_rid"]: ref["selected"]["path"] for ref in report["assembly_refs"]}
    assert selected[1] == selected[2]
    assert selected[1].endswith("v2/Contoso.Utils.dll")
    assert report["assembly_refs"][0]["confidence"] == "weak"


def test_redirection_changes_method_signature_seen_by_analysis(fixture_paths):
    exact = _resolve(fixture_paths, "exact_identity")
    loose = _resolve(fixture_paths, "name_only_highest_version")
    exact_target = exact["member_refs"][0]["target"]
    loose_target = loose["member_refs"][0]["target"]
    assert exact_target["signature_matches_ref"] is True
    assert loose_target["signature_matches_ref"] is False
    assert loose_target["signature_hex"] != exact_target["signature_hex"]


def test_no_runtime_claim_without_configuration(fixture_paths):
    report = _resolve(fixture_paths, "exact_identity")
    assert report["runtime_claim"].startswith("none")
    assert report["layer"] == "static-policy"


def test_candidate_identity_comes_from_the_file_not_the_name(fixture_paths):
    parsed = identity.parse_assembly(str(fixture_paths["candidate_v2"]))
    assert parsed.identity.version_str == "2.0.0.0"
    assert parsed.identity.token_hex is not None
