import copy
import json

import pytest

from approval_tool.core import (
    ApprovalNotGrantedError,
    AssetNotFoundError,
    Decision,
    DuplicateAssetRefError,
    approve_rotation,
    index_assets,
    inspect_asset,
    trim_approval_output_v1,
    trim_bom_to_cyclonedx_1_6,
)
from approval_tool.inventory import (
    NAMESAKE_KEY_REF,
    NEW_KEY_REF,
    OLD_CERT_REF,
    OLD_KEY_REF,
    build_pre_rotation_bom_dict,
    build_rotation_request,
)
from approval_tool.scenario import run_scenario


def _approved_bundle():
    bom = build_pre_rotation_bom_dict()
    request = build_rotation_request()
    bundle = approve_rotation(bom, request, decoy_refs=[NAMESAKE_KEY_REF])
    return bom, request, bundle


def test_fixture_uses_two_rotation_keys_two_certs_and_explicit_refs():
    bom = build_pre_rotation_bom_dict()
    assets = index_assets(bom)

    assert OLD_KEY_REF in assets
    assert NEW_KEY_REF in assets
    assert OLD_CERT_REF in assets
    assert "asset:cert:checkout-signing-2026q4" in assets

    old_cert = assets[OLD_CERT_REF]
    assert old_cert["cryptoProperties"]["certificateProperties"]["subjectPublicKeyRef"] == OLD_KEY_REF

    same_named = [ref for ref, asset in assets.items() if asset.get("name") == "checkout-signing-key"]
    assert {OLD_KEY_REF, NEW_KEY_REF, NAMESAKE_KEY_REF}.issubset(set(same_named))


def test_approved_rotation_classifies_current_use_and_keeps_history():
    _, _, bundle = _approved_bundle()
    decision_by_ref = {item["asset_ref"]: item for item in bundle["approval"]["decisions"]}

    old_decision = decision_by_ref[OLD_KEY_REF]
    new_decision = decision_by_ref[NEW_KEY_REF]

    assert old_decision["decision"] == Decision.VERIFICATION_ONLY.value
    assert old_decision["current_permissions"]["new_use"] == "denied"
    assert old_decision["current_permissions"]["verify_historical_signatures"] == "allowed"
    assert [item["certificate_ref"] for item in old_decision["historical_certificate_associations"]] == [OLD_CERT_REF]

    assert new_decision["decision"] == Decision.NEW_USE_ALLOWED.value
    assert new_decision["current_permissions"]["new_use"] == "allowed"

    assets = index_assets(bundle["bom"])
    assert assets[OLD_KEY_REF]["cryptoProperties"]["relatedCryptoMaterialProperties"]["state"] == "deactivated"
    assert assets[NEW_KEY_REF]["cryptoProperties"]["relatedCryptoMaterialProperties"]["state"] == "active"
    assert assets[OLD_CERT_REF]["cryptoProperties"]["certificateProperties"]["subjectPublicKeyRef"] == OLD_KEY_REF


def test_updates_are_bom_ref_scoped_and_same_name_asset_is_untouched():
    before, _, bundle = _approved_bundle()
    before_namesake = copy.deepcopy(index_assets(before)[NAMESAKE_KEY_REF])
    after_namesake = index_assets(bundle["bom"])[NAMESAKE_KEY_REF]

    assert after_namesake == before_namesake
    assert after_namesake["cryptoProperties"]["relatedCryptoMaterialProperties"]["state"] == "active"
    assert bundle["archive"]["audit_events"][-1]["protected_refs"] == [NAMESAKE_KEY_REF]


def test_old_schema_readback_is_pending_but_history_remains_confirmed():
    _, _, bundle = _approved_bundle()
    approval_v1 = trim_approval_output_v1(bundle["approval"])
    bom_1_6 = trim_bom_to_cyclonedx_1_6(bundle["bom"])

    readback = inspect_asset(bom_1_6, OLD_KEY_REF, approval_v1)

    assert readback["material_state"] == "deactivated"
    assert readback["decision"] == Decision.PENDING_CONFIRMATION.value
    assert readback["reconstructed_usage_posture"] == Decision.VERIFICATION_ONLY.value
    assert readback["confirmation_status"] == "pending_confirmation"
    assert readback["historical_verification_relation"]["certificate_refs"] == [OLD_CERT_REF]
    assert readback["historical_verification_relation"]["status"] == "confirmed"
    assert readback["inventory_usage_posture"] == Decision.VERIFICATION_ONLY.value
    assert "approval-v1:extended-decision-field-omitted" in readback["evidence_gaps"]
    assert "approval-output:evidence-block-missing" in readback["evidence_gaps"]
    assert "cyclonedx-1.6:certificateState-1.7-omitted" in readback["evidence_gaps"]
    assert bom_1_6["specVersion"] == "1.6"
    old_cert = index_assets(bom_1_6)[OLD_CERT_REF]
    assert "certificateState" not in old_cert["cryptoProperties"]["certificateProperties"]

    new_readback = inspect_asset(bom_1_6, NEW_KEY_REF, approval_v1)
    assert new_readback["inventory_usage_posture"] == Decision.NEW_USE_ALLOWED.value
    assert new_readback["confirmation_status"] == Decision.PENDING_CONFIRMATION.value


def test_approval_output_and_archive_are_distinct_records():
    _, _, bundle = _approved_bundle()

    assert bundle["approval"]["document_kind"] == "approval_decision"
    assert bundle["archive"]["document_kind"] == "internal_rotation_archive"
    assert "audit_events" not in bundle["approval"]
    assert any(
        event["action"] == "new-use.permission_withdrawn" and event["asset_ref"] == OLD_KEY_REF
        for event in bundle["archive"]["audit_events"]
    )


def test_unknown_ref_and_unapproved_request_are_rejected():
    bom = build_pre_rotation_bom_dict()
    request = build_rotation_request()

    bad_ref = copy.deepcopy(request)
    bad_ref["old_asset_ref"] = "asset:key:does-not-exist"
    with pytest.raises(AssetNotFoundError):
        approve_rotation(bom, bad_ref)

    not_approved = copy.deepcopy(request)
    not_approved["status"] = "submitted"
    not_approved["decision"] = "pending"
    with pytest.raises(ApprovalNotGrantedError):
        approve_rotation(bom, not_approved)


def test_duplicate_bom_ref_is_rejected():
    bom = build_pre_rotation_bom_dict()
    duplicate = copy.deepcopy(bom["components"][1])
    duplicate["bom-ref"] = OLD_KEY_REF
    bom["components"].append(duplicate)

    with pytest.raises(DuplicateAssetRefError):
        index_assets(bom)


def test_end_to_end_scenario_writes_passing_receipt(tmp_path):
    report = run_scenario(str(tmp_path))

    assert report["all_passed"] is True
    assert report["summary"]["failed"] == 0
    for filename in (
        "01-before-rotation.cdx-1.7.json",
        "03-approval-output.evidence-v2.json",
        "04-internal-archive.json",
        "06-approval-output.old-v1-trimmed.json",
        "07-after-rotation.cdx-1.6-trimmed.json",
        "verification-report.json",
        "verification-report.md",
    ):
        assert (tmp_path / filename).is_file()

    persisted = json.loads((tmp_path / "verification-report.json").read_text(encoding="utf-8"))
    assert persisted["all_passed"] is True
