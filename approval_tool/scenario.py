"""End-to-end fictional rotation scenario and read-back verification."""

from __future__ import annotations

import argparse
import os
from typing import Any, Optional

from cyclonedx.model.bom import Bom

from .core import (
    ConfirmationStatus,
    Decision,
    approve_rotation,
    canonical_digest,
    inspect_asset,
    read_json,
    trim_approval_output_v1,
    trim_bom_to_cyclonedx_1_6,
    verify_name_scope_unchanged,
    write_json,
)
from .inventory import (
    NAMESAKE_KEY_REF,
    NEW_KEY_REF,
    OLD_CERT_REF,
    OLD_KEY_REF,
    build_pre_rotation_bom_dict,
    build_rotation_request,
)


DEFAULT_OUTPUT_DIR = os.path.join("artifacts", "key-rotation-approval")


def _check(checks: list[dict[str, Any]], check_id: str, title: str, passed: bool, details: Any) -> bool:
    checks.append(
        {
            "id": check_id,
            "title": title,
            "status": "passed" if passed else "failed",
            "details": details,
        }
    )
    return passed


def _cert_ref(bom: dict[str, Any], cert_ref: str) -> Optional[str]:
    from .core import certificate_properties, get_asset

    return certificate_properties(get_asset(bom, cert_ref)).get("subjectPublicKeyRef")


def _has_certificate_state(bom: dict[str, Any], cert_ref: str) -> bool:
    from .core import certificate_properties, get_asset

    return "certificateState" in certificate_properties(get_asset(bom, cert_ref))


def run_scenario(output_dir: str = DEFAULT_OUTPUT_DIR) -> dict[str, Any]:
    os.makedirs(output_dir, exist_ok=True)

    before_path = os.path.join(output_dir, "01-before-rotation.cdx-1.7.json")
    request_path = os.path.join(output_dir, "02-rotation-request.json")
    approval_path = os.path.join(output_dir, "03-approval-output.evidence-v2.json")
    archive_path = os.path.join(output_dir, "04-internal-archive.json")
    after_17_path = os.path.join(output_dir, "05-after-rotation.cdx-1.7.evidence.json")
    approval_v1_path = os.path.join(output_dir, "06-approval-output.old-v1-trimmed.json")
    after_16_path = os.path.join(output_dir, "07-after-rotation.cdx-1.6-trimmed.json")
    report_json_path = os.path.join(output_dir, "verification-report.json")
    report_md_path = os.path.join(output_dir, "verification-report.md")

    before_bom = build_pre_rotation_bom_dict()
    request = build_rotation_request()
    write_json(before_path, before_bom)
    write_json(request_path, request)

    bundle = approve_rotation(
        before_bom,
        request,
        before_file=os.path.basename(before_path),
        after_file=os.path.basename(after_17_path),
        approval_file=os.path.basename(approval_path),
        decoy_refs=[NAMESAKE_KEY_REF],
    )
    after_bom_17 = bundle["bom"]
    approval_v2 = bundle["approval"]
    archive = bundle["archive"]

    approval_v1 = trim_approval_output_v1(approval_v2)
    after_bom_16 = trim_bom_to_cyclonedx_1_6(after_bom_17)

    write_json(approval_path, approval_v2)
    write_json(archive_path, archive)
    write_json(after_17_path, after_bom_17)
    write_json(approval_v1_path, approval_v1)
    write_json(after_16_path, after_bom_16)

    # Re-read everything from disk so verification is not based on in-memory objects.
    reread_before = read_json(before_path)
    reread_request = read_json(request_path)
    reread_approval_v2 = read_json(approval_path)
    reread_archive = read_json(archive_path)
    reread_after_17 = read_json(after_17_path)
    reread_approval_v1 = read_json(approval_v1_path)
    reread_after_16 = read_json(after_16_path)

    parse_results = {}
    for label, document in (
        ("before-1.7", reread_before),
        ("after-1.7", reread_after_17),
        ("after-1.6", reread_after_16),
    ):
        Bom.from_json(document)  # type: ignore[attr-defined]
        parse_results[label] = "Bom.from_json ok"

    enriched_old = inspect_asset(reread_after_17, OLD_KEY_REF, reread_approval_v2)
    enriched_new = inspect_asset(reread_after_17, NEW_KEY_REF, reread_approval_v2)
    oldfmt_old = inspect_asset(reread_after_16, OLD_KEY_REF, reread_approval_v1)
    oldfmt_new = inspect_asset(reread_after_16, NEW_KEY_REF, reread_approval_v1)
    namesake = verify_name_scope_unchanged(reread_before, reread_after_17, [NAMESAKE_KEY_REF])

    checks: list[dict[str, Any]] = []

    _check(
        checks,
        "request.approved-once",
        "提交的是一次已批准轮换",
        reread_request.get("status") == "approved" and reread_request.get("rotation_id") == request["rotation_id"],
        {"rotation_id": reread_request.get("rotation_id")},
    )
    _check(
        checks,
        "enriched.old.verify-only",
        "新版证据输出：旧材料禁止新用且仅用于历史核验",
        enriched_old["decision"] == Decision.VERIFICATION_ONLY.value
        and enriched_old["current_new_use_permission"] == "denied"
        and enriched_old["confirmation_status"] == ConfirmationStatus.CONFIRMED.value
        and enriched_old["material_state"] == "deactivated",
        enriched_old,
    )
    _check(
        checks,
        "enriched.new.allow-new-use",
        "新版证据输出：新材料允许新用",
        enriched_new["decision"] == Decision.NEW_USE_ALLOWED.value
        and enriched_new["current_new_use_permission"] == "allowed"
        and enriched_new["confirmation_status"] == ConfirmationStatus.CONFIRMED.value
        and enriched_new["material_state"] == "active",
        enriched_new,
    )
    _check(
        checks,
        "history.old-certificate-link-preserved",
        "旧证书仍通过清单内 bom-ref 关联旧密钥",
        _cert_ref(reread_after_17, OLD_CERT_REF) == OLD_KEY_REF
        and OLD_CERT_REF in enriched_old["historical_verification_relation"]["certificate_refs"],
        {
            "certificate_ref": OLD_CERT_REF,
            "subject_public_key_ref_after_1_7": _cert_ref(reread_after_17, OLD_CERT_REF),
            "readback": enriched_old["historical_verification_relation"],
        },
    )
    _check(
        checks,
        "history.old-link-survives-cdx16-trim",
        "裁剪到 CycloneDX 1.6 后历史证书关系仍可读回",
        _cert_ref(reread_after_16, OLD_CERT_REF) == OLD_KEY_REF
        and oldfmt_old["historical_verification_relation"]["status"] == "confirmed"
        and oldfmt_old["historical_verification_relation"]["certificate_refs"] == [OLD_CERT_REF],
        oldfmt_old["historical_verification_relation"],
    )
    _check(
        checks,
        "old-format.evidence-gap-pending",
        "旧审批 schema 丢失扩展判定/证据时标记为待确认",
        oldfmt_old["decision"] == Decision.PENDING_CONFIRMATION.value
        and oldfmt_old["confirmation_status"] == ConfirmationStatus.PENDING.value
        and oldfmt_old["inventory_usage_posture"] == Decision.VERIFICATION_ONLY.value
        and any("approval-v1" in gap for gap in oldfmt_old["evidence_gaps"])
        and any("evidence" in gap for gap in oldfmt_old["evidence_gaps"]),
        oldfmt_old,
    )
    _check(
        checks,
        "old-format.cdx17-state-gap-pending",
        "CycloneDX 1.7 证书生命周期状态裁剪后识别为 schema 缺口",
        any("cyclonedx-1.6:certificateState-1.7-omitted" in gap for gap in oldfmt_old["evidence_gaps"])
        and not _has_certificate_state(reread_after_16, OLD_CERT_REF),
        {"gaps": oldfmt_old["evidence_gaps"]},
    )
    _check(
        checks,
        "old-format.new-key-pending-without-evidence",
        "旧格式中 active 状态只能推断用途姿态，不能替代新用批准证据",
        oldfmt_new["inventory_usage_posture"] == Decision.NEW_USE_ALLOWED.value
        and oldfmt_new["current_new_use_permission"] == ConfirmationStatus.PENDING.value
        and oldfmt_new["confirmation_status"] == ConfirmationStatus.PENDING.value,
        oldfmt_new,
    )
    _check(
        checks,
        "namesake.not-updated",
        "同名但不同 bom-ref 的材料保持不变",
        len(namesake) == 1 and namesake[0]["unchanged"] is True,
        namesake,
    )
    _check(
        checks,
        "records.approval-and-archive-distinct",
        "批准输出与内部存档类型、内容和审计职责可区分",
        reread_approval_v2["document_kind"] == "approval_decision"
        and reread_archive["document_kind"] == "internal_rotation_archive"
        and reread_approval_v2["schema"] != reread_archive["schema"]
        and "audit_events" not in reread_approval_v2
        and any(event["action"] == "new-use.permission_withdrawn" for event in reread_archive["audit_events"])
        and reread_approval_v2["rotation_id"] == reread_archive["rotation_id"],
        {
            "approval_kind": reread_approval_v2["document_kind"],
            "archive_kind": reread_archive["document_kind"],
            "archive_has_withdrawal_audit": any(
                event["action"] == "new-use.permission_withdrawn" for event in reread_archive["audit_events"]
            ),
        },
    )
    digest_check = {
        "approval_matches_integrity": (
            reread_archive["integrity"]["approval_output_digest"] == canonical_digest(reread_approval_v2)
            and reread_archive["artifacts"]["approval_output"]["digest"] == canonical_digest(reread_approval_v2)
        ),
        "after_bom_matches_integrity": (
            reread_archive["integrity"]["after_inventory_digest"] == canonical_digest(reread_after_17)
            and reread_archive["artifacts"]["after_inventory"]["digest"] == canonical_digest(reread_after_17)
        ),
        "before_bom_matches_archive": (
            reread_archive["artifacts"]["before_inventory"]["digest"] == canonical_digest(reread_before)
        ),
    }
    _check(
        checks,
        "records.integrity-digests-match",
        "内部存档中的摘要与重新读入的批准输出和清单一致",
        all(digest_check.values()),
        digest_check,
    )
    _check(
        checks,
        "cyclonedx.library-reread",
        "生成的 BOM 可由 CycloneDX 库重新读入",
        all(value == "Bom.from_json ok" for value in parse_results.values()),
        parse_results,
    )

    failed = [check for check in checks if check["status"] != "passed"]
    all_passed = not failed
    passed_count = len(checks) - len(failed)
    report = {
        "scenario": "fictional-two-keys-two-certificates-rotation",
        "all_passed": all_passed,
        "summary": {"total": len(checks), "passed": passed_count, "failed": len(failed)},
        "files": {
            "before_bom": os.path.basename(before_path),
            "rotation_request": os.path.basename(request_path),
            "approval_v2": os.path.basename(approval_path),
            "internal_archive": os.path.basename(archive_path),
            "after_bom_1_7": os.path.basename(after_17_path),
            "approval_v1_trimmed": os.path.basename(approval_v1_path),
            "after_bom_1_6_trimmed": os.path.basename(after_16_path),
        },
        "asset_readback": {
            "enriched_v2": {OLD_KEY_REF: enriched_old, NEW_KEY_REF: enriched_new},
            "old_schema": {OLD_KEY_REF: oldfmt_old, NEW_KEY_REF: oldfmt_new},
        },
        "namesake_scope_check": namesake,
        "cyclonedx_parse": parse_results,
        "checks": checks,
    }
    write_json(report_json_path, report)
    with open(report_md_path, "w", encoding="utf-8") as handle:
        handle.write("# Key rotation approval verification\n\n")
        handle.write(f"Result: **{'PASS' if all_passed else 'FAIL'}** ({passed_count}/{len(checks)})\n\n")
        handle.write("| Check | Result |\n|---|---|\n")
        for check in checks:
            handle.write(f"| {check['title']} | {check['status']} |\n")
        handle.write("\n## Asset read-back\n\n")
        for label, item in (
            ("old/enriched", enriched_old),
            ("new/enriched", enriched_new),
            ("old/old-schema", oldfmt_old),
            ("new/old-schema", oldfmt_new),
        ):
            history = item["historical_verification_relation"]
            cert_refs = ", ".join(f"`{ref}`" for ref in history["certificate_refs"]) or "none"
            gaps = ", ".join(f"`{gap}`" for gap in item["evidence_gaps"]) or "none"
            handle.write(
                f"- `{label}` `{item['asset_ref']}`: decision=`{item['decision']}`, "
                f"inventory_posture=`{item['inventory_usage_posture']}`, "
                f"new_use=`{item['current_new_use_permission']}`, "
                f"confirmation=`{item['confirmation_status']}`, "
                f"history_status=`{history['status']}`, certificate_refs={cert_refs}, gaps={gaps}\n"
            )
    return report


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run the fictional key-rotation approval scenario.")
    parser.add_argument("--out", default=DEFAULT_OUTPUT_DIR, help="artifact output directory")
    args = parser.parse_args(argv)
    report = run_scenario(args.out)
    print(f"verification: {report['summary']['passed']}/{report['summary']['total']} passed")
    if not report["all_passed"]:
        for check in report["checks"]:
            if check["status"] != "passed":
                print(f"FAILED {check['id']}: {check['title']}")
        return 1
    print(os.path.join(args.out, "verification-report.md"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
