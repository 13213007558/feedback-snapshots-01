"""Asset-id based approval logic for CycloneDX key/certificate rotations.

The helper functions in this module intentionally mutate rotation targets by
CycloneDX ``bom-ref`` only.  Component names are display data and are never
used as an update key.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


NAMESPACE = "approval.example"

APPROVAL_OUTPUT_V2_SCHEMA = "https://example.invalid/schemas/key-rotation-approval-v2.json"
APPROVAL_OUTPUT_V1_SCHEMA = "https://example.invalid/schemas/key-rotation-approval-v1.json"
ARCHIVE_V1_SCHEMA = "https://example.invalid/schemas/key-rotation-archive-v1.json"
REQUEST_V1_SCHEMA = "https://example.invalid/schemas/key-rotation-request-v1.json"


class Decision(str, Enum):
    """Approval posture used by this tool."""

    NEW_USE_ALLOWED = "new_use_allowed"
    VERIFICATION_ONLY = "verification_only"
    PENDING_CONFIRMATION = "pending_confirmation"
    NOT_IN_ROTATION = "not_in_rotation"


class NewUsePermission(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    PENDING = "pending_confirmation"
    UNTOUCHED = "untouched"


class ConfirmationStatus(str, Enum):
    CONFIRMED = "confirmed"
    PENDING = "pending_confirmation"


class ApprovalToolError(ValueError):
    """Base error for invalid approval operations."""


class AssetNotFoundError(ApprovalToolError):
    """Raised when a requested bom-ref is absent."""


class DuplicateAssetRefError(ApprovalToolError):
    """Raised when a BOM does not have unique bom-ref values."""


class ApprovalNotGrantedError(ApprovalToolError):
    """Raised when a rotation request has not been approved."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_digest(value: Any) -> str:
    """Return a stable SHA-256 digest for JSON-compatible data."""

    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def write_json(path: str, value: Any) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def iter_components(bom: dict[str, Any]) -> Any:
    """Yield all components, including nested components."""

    stack = list(bom.get("components") or [])
    while stack:
        component = stack.pop()
        if not isinstance(component, dict):
            continue
        yield component
        stack.extend(component.get("components") or [])


def index_assets(bom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index components by their in-BOM asset identifier."""

    indexed: dict[str, dict[str, Any]] = {}
    for component in iter_components(bom):
        ref = component.get("bom-ref")
        if not ref:
            continue
        if ref in indexed:
            raise DuplicateAssetRefError(f"duplicate bom-ref in inventory: {ref}")
        indexed[ref] = component
    return indexed


def get_asset(bom: dict[str, Any], asset_ref: str) -> dict[str, Any]:
    try:
        return index_assets(bom)[asset_ref]
    except KeyError as exc:
        raise AssetNotFoundError(f"asset bom-ref not found: {asset_ref}") from exc


def asset_name(asset: dict[str, Any]) -> str:
    return str(asset.get("name") or "")


def crypto_properties(asset: dict[str, Any]) -> dict[str, Any]:
    props = asset.get("cryptoProperties")
    return props if isinstance(props, dict) else {}


def related_material_properties(asset: dict[str, Any]) -> dict[str, Any]:
    props = crypto_properties(asset).get("relatedCryptoMaterialProperties")
    return props if isinstance(props, dict) else {}


def certificate_properties(asset: dict[str, Any]) -> dict[str, Any]:
    props = crypto_properties(asset).get("certificateProperties")
    return props if isinstance(props, dict) else {}


def material_state(asset: dict[str, Any]) -> Optional[str]:
    state = related_material_properties(asset).get("state")
    return state if isinstance(state, str) else None


def get_property(asset: dict[str, Any], name: str) -> Optional[str]:
    for prop in asset.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == name:
            value = prop.get("value")
            return value if isinstance(value, str) else None
    return None


def set_property(asset: dict[str, Any], name: str, value: str) -> None:
    properties = asset.setdefault("properties", [])
    for prop in properties:
        if isinstance(prop, dict) and prop.get("name") == name:
            prop["value"] = value
            return
    properties.append({"name": name, "value": value})


def _set_material_state(asset: dict[str, Any], state: str) -> None:
    crypto = asset.setdefault("cryptoProperties", {})
    material = crypto.setdefault("relatedCryptoMaterialProperties", {})
    material["state"] = state


def _set_certificate_state(certificate: dict[str, Any], state: str, reason: str) -> None:
    cert_props = certificate.setdefault("cryptoProperties", {}).setdefault("certificateProperties", {})
    cert_props["certificateState"] = [{"state": state, "reason": reason}]


def find_certificate_associations(bom: dict[str, Any], key_ref: str) -> list[dict[str, str]]:
    """Find explicit certificate -> key associations for ``key_ref``.

    Supports the CycloneDX 1.6 ``subjectPublicKeyRef`` field and CycloneDX 1.7
    ``relatedCryptographicAssets`` association list.
    """

    associations: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for component in iter_components(bom):
        crypto = crypto_properties(component)
        if crypto.get("assetType") != "certificate":
            continue
        cert_props = certificate_properties(component)
        cert_ref = str(component.get("bom-ref") or "")

        if cert_props.get("subjectPublicKeyRef") == key_ref:
            item = (cert_ref, "certificateProperties.subjectPublicKeyRef")
            if item not in seen:
                seen.add(item)
                associations.append(
                    {
                        "certificate_ref": cert_ref,
                        "certificate_name": asset_name(component),
                        "key_ref": key_ref,
                        "basis": item[1],
                    }
                )

        cert_related = cert_props.get("relatedCryptographicAssets")
        crypto_related = crypto.get("relatedCryptographicAssets")
        for basis, relations in (
            ("certificateProperties.relatedCryptographicAssets", cert_related),
            ("cryptoProperties.relatedCryptographicAssets", crypto_related),
        ):
            if not isinstance(relations, list):
                continue
            for relation in relations:
                if isinstance(relation, dict) and relation.get("ref") == key_ref:
                    item = (cert_ref, basis)
                    if item not in seen:
                        seen.add(item)
                        associations.append(
                            {
                                "certificate_ref": cert_ref,
                                "certificate_name": asset_name(component),
                                "key_ref": key_ref,
                                "basis": basis,
                            }
                        )

    return sorted(associations, key=lambda item: (item["certificate_ref"], item["basis"]))


def validate_approved_request(bom: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    if request.get("status") != "approved" and request.get("decision") != "approved":
        raise ApprovalNotGrantedError("rotation request does not contain an approval")

    old_ref = request.get("old_asset_ref")
    new_ref = request.get("new_asset_ref")
    if not isinstance(old_ref, str) or not isinstance(new_ref, str):
        raise ApprovalToolError("old_asset_ref and new_asset_ref are required")
    if old_ref == new_ref:
        raise ApprovalToolError("old_asset_ref and new_asset_ref must differ")

    old_asset = get_asset(bom, old_ref)
    new_asset = get_asset(bom, new_ref)
    for label, asset in (("old_asset_ref", old_asset), ("new_asset_ref", new_asset)):
        if crypto_properties(asset).get("assetType") != "related-crypto-material":
            raise ApprovalToolError(f"{label} is not a related-crypto-material asset")

    return {
        "old_ref": old_ref,
        "new_ref": new_ref,
        "old_asset": old_asset,
        "new_asset": new_asset,
        "old_certificate_associations": find_certificate_associations(bom, old_ref),
        "new_certificate_associations": find_certificate_associations(bom, new_ref),
    }


def apply_rotation(
    bom: dict[str, Any],
    request: dict[str, Any],
    *,
    approved_at: Optional[str] = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return a rotated BOM and current decisions, targeting bom-ref only."""

    plan = validate_approved_request(bom, request)
    rotated = copy.deepcopy(bom)
    assets = index_assets(rotated)
    old_ref = plan["old_ref"]
    new_ref = plan["new_ref"]
    old_asset = assets[old_ref]
    new_asset = assets[new_ref]
    rotation_id = str(request.get("rotation_id") or "rotation-unknown")
    timestamp = approved_at or str(request.get("approved_at") or utc_now_iso())
    reason = f"approved rotation {rotation_id}; deactivated for new use, retained for historical signature verification"

    old_associations = find_certificate_associations(rotated, old_ref)
    new_associations = find_certificate_associations(rotated, new_ref)

    _set_material_state(old_asset, "deactivated")
    set_property(old_asset, f"{NAMESPACE}/rotation-id", rotation_id)
    set_property(old_asset, f"{NAMESPACE}/permission-new-use", NewUsePermission.DENIED.value)
    set_property(old_asset, f"{NAMESPACE}/permission-historical-verification", NewUsePermission.ALLOWED.value)

    _set_material_state(new_asset, "active")
    set_property(new_asset, f"{NAMESPACE}/rotation-id", rotation_id)
    set_property(new_asset, f"{NAMESPACE}/permission-new-use", NewUsePermission.ALLOWED.value)
    set_property(new_asset, f"{NAMESPACE}/permission-historical-verification", NewUsePermission.ALLOWED.value)

    for association in old_associations:
        certificate = assets.get(association["certificate_ref"])
        if certificate is not None:
            _set_certificate_state(certificate, "deactivated", reason)
            cert_props = certificate_properties(certificate)
            cert_props.setdefault("relatedCryptographicAssets", []).append(
                {
                    "type": "publicKey",
                    "ref": old_ref,
                }
            )

    for association in new_associations:
        certificate = assets.get(association["certificate_ref"])
        if certificate is not None:
            _set_certificate_state(certificate, "active", f"active replacement from approved rotation {rotation_id}")
            cert_props = certificate_properties(certificate)
            cert_props.setdefault("relatedCryptographicAssets", []).append(
                {
                    "type": "publicKey",
                    "ref": new_ref,
                }
            )

    decisions = [
        {
            "asset_ref": old_ref,
            "asset_name": asset_name(old_asset),
            "decision": Decision.VERIFICATION_ONLY.value,
            "material_state": "deactivated",
            "current_permissions": {
                "new_use": NewUsePermission.DENIED.value,
                "apply_protection": NewUsePermission.DENIED.value,
                "verify_historical_signatures": NewUsePermission.ALLOWED.value,
            },
            "historical_certificate_associations": old_associations,
            "updated_by_asset_ref": old_ref,
            "decided_at": timestamp,
        },
        {
            "asset_ref": new_ref,
            "asset_name": asset_name(new_asset),
            "decision": Decision.NEW_USE_ALLOWED.value,
            "material_state": "active",
            "current_permissions": {
                "new_use": NewUsePermission.ALLOWED.value,
                "apply_protection": NewUsePermission.ALLOWED.value,
                "verify_historical_signatures": NewUsePermission.ALLOWED.value,
            },
            "historical_certificate_associations": new_associations,
            "updated_by_asset_ref": new_ref,
            "decided_at": timestamp,
        },
    ]
    return rotated, decisions


def build_evidence(
    request: dict[str, Any], before_bom: dict[str, Any], after_bom: dict[str, Any]
) -> list[dict[str, Any]]:
    rotation_id = str(request.get("rotation_id") or "rotation-unknown")
    return [
        {
            "id": f"{rotation_id}:evidence:approval-request",
            "kind": "approval-request",
            "digest": canonical_digest(request),
            "statement": "Signed/fictional change-board approval represented by the submitted request digest.",
        },
        {
            "id": f"{rotation_id}:evidence:before-inventory",
            "kind": "cyclonedx-inventory-snapshot",
            "spec_version": before_bom.get("specVersion"),
            "digest": canonical_digest(before_bom),
            "statement": "Pre-rotation CycloneDX inventory was re-read and digested before mutation.",
        },
        {
            "id": f"{rotation_id}:evidence:after-inventory",
            "kind": "cyclonedx-inventory-snapshot",
            "spec_version": after_bom.get("specVersion"),
            "digest": canonical_digest(after_bom),
            "statement": "Post-rotation CycloneDX inventory contains the current material states and references.",
        },
        {
            "id": f"{rotation_id}:evidence:asset-id-association",
            "kind": "association-rule",
            "statement": "Updates and certificate relationships are resolved by unique CycloneDX bom-ref, never by name.",
        },
    ]


def build_approval_output(
    request: dict[str, Any],
    decisions: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "$schema": APPROVAL_OUTPUT_V2_SCHEMA,
        "schema": "key-rotation-approval-output/v2",
        "document_kind": "approval_decision",
        "distribution": "requester-facing-approval-output",
        "rotation_id": request.get("rotation_id"),
        "issued_at": request.get("approved_at"),
        "decisions": decisions,
        "evidence": evidence,
    }


def build_internal_archive(
    request: dict[str, Any],
    approval: dict[str, Any],
    before_bom: dict[str, Any],
    after_bom: dict[str, Any],
    *,
    before_file: str,
    after_file: str,
    approval_file: str,
    decoy_refs: Optional[list[str]] = None,
) -> dict[str, Any]:
    rotation_id = request.get("rotation_id")
    old_ref = request.get("old_asset_ref")
    new_ref = request.get("new_asset_ref")
    old_associations = find_certificate_associations(after_bom, str(old_ref))
    return {
        "$schema": ARCHIVE_V1_SCHEMA,
        "schema": "key-rotation-internal-archive/v1",
        "document_kind": "internal_rotation_archive",
        "distribution": "internal-record-not-an-approval-token",
        "rotation_id": rotation_id,
        "archived_at": utc_now_iso(),
        "request": request,
        "audit_events": [
            {
                "action": "rotation.approved",
                "at": request.get("approved_at"),
                "actor": request.get("approved_by"),
                "asset_refs": [old_ref, new_ref],
            },
            {
                "action": "new-use.permission_withdrawn",
                "at": request.get("approved_at"),
                "asset_ref": old_ref,
                "previous_permission": NewUsePermission.ALLOWED.value,
                "current_permission": NewUsePermission.DENIED.value,
                "reason": "old material stopped issuing new signatures; retained only to check historical signatures",
            },
            {
                "action": "new-use.permission_granted",
                "at": request.get("approved_at"),
                "asset_ref": new_ref,
                "previous_permission": NewUsePermission.PENDING.value,
                "current_permission": NewUsePermission.ALLOWED.value,
            },
            {
                "action": "historical-verification.relation_retained",
                "at": request.get("approved_at"),
                "asset_ref": old_ref,
                "certificate_associations": old_associations,
            },
            {
                "action": "namesake.update_scope_checked",
                "at": request.get("approved_at"),
                "targeting_rule": "bom-ref-exact-match",
                "protected_refs": decoy_refs or [],
            },
        ],
        "artifacts": {
            "before_inventory": {"path": before_file, "digest": canonical_digest(before_bom)},
            "after_inventory": {"path": after_file, "digest": canonical_digest(after_bom)},
            "approval_output": {"path": approval_file, "digest": canonical_digest(approval)},
        },
        "integrity": {
            "approval_output_digest": canonical_digest(approval),
            "after_inventory_digest": canonical_digest(after_bom),
        },
    }


def approve_rotation(
    before_bom: dict[str, Any],
    request: dict[str, Any],
    *,
    before_file: str = "before.cdx.json",
    after_file: str = "after.cdx.json",
    approval_file: str = "approval-v2.json",
    decoy_refs: Optional[list[str]] = None,
) -> dict[str, Any]:
    after_bom, decisions = apply_rotation(before_bom, request)
    evidence = build_evidence(request, before_bom, after_bom)
    evidence_ids = [item["id"] for item in evidence]
    for decision in decisions:
        decision["evidence_refs"] = evidence_ids
    approval = build_approval_output(request, decisions, evidence)
    archive = build_internal_archive(
        request,
        approval,
        before_bom,
        after_bom,
        before_file=before_file,
        after_file=after_file,
        approval_file=approval_file,
        decoy_refs=decoy_refs,
    )
    return {"bom": after_bom, "approval": approval, "archive": archive}


def trim_approval_output_v1(approval_v2: dict[str, Any]) -> dict[str, Any]:
    """Crop an evidence-rich v2 decision to the old v1 approval schema."""

    old_decisions = []
    for decision in approval_v2.get("decisions") or []:
        old_decisions.append(
            {
                "assetRef": decision.get("asset_ref"),
                "name": decision.get("asset_name"),
                "materialState": decision.get("material_state"),
            }
        )
    return {
        "$schema": APPROVAL_OUTPUT_V1_SCHEMA,
        "schema": "key-rotation-approval-output/v1",
        "document_kind": "approval_decision",
        "rotation_id": approval_v2.get("rotation_id"),
        "decisions": old_decisions,
    }


def trim_bom_to_cyclonedx_1_6(bom_1_7: dict[str, Any]) -> dict[str, Any]:
    """Crop CycloneDX 1.7-only fields while retaining 1.6 relations/state."""

    trimmed = copy.deepcopy(bom_1_7)
    trimmed["$schema"] = "http://cyclonedx.org/schema/bom-1.6.schema.json"
    trimmed["specVersion"] = "1.6"

    for component in iter_components(trimmed):
        cert_props = certificate_properties(component)
        cert_props.pop("certificateState", None)
        cert_props.pop("relatedCryptographicAssets", None)
        crypto = crypto_properties(component)
        crypto.pop("relatedCryptographicAssets", None)

    return trimmed


def _find_claim(approval: Optional[dict[str, Any]], asset_ref: str) -> Optional[dict[str, Any]]:
    if not approval:
        return None
    for key in ("decisions",):
        for decision in approval.get(key) or []:
            if not isinstance(decision, dict):
                continue
            if decision.get("asset_ref") == asset_ref or decision.get("assetRef") == asset_ref:
                return decision
    return None


class RelatedState(str, Enum):
    ACTIVE = "active"
    DEACTIVATED = "deactivated"
    PRE_ACTIVATION = "pre-activation"
    SUSPENDED = "suspended"
    COMPROMISED = "compromised"
    DESTROYED = "destroyed"


def classify_inventory_usage(bom: dict[str, Any], asset_ref: str) -> str:
    """Infer the material usage posture from CycloneDX state and asset links."""

    asset = get_asset(bom, asset_ref)
    state = material_state(asset)
    associations = find_certificate_associations(bom, asset_ref)

    if state == RelatedState.DEACTIVATED and associations:
        return Decision.VERIFICATION_ONLY.value
    if state == RelatedState.ACTIVE:
        return Decision.NEW_USE_ALLOWED.value
    return Decision.PENDING_CONFIRMATION.value


def inspect_asset(
    bom: dict[str, Any],
    asset_ref: str,
    approval: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Re-read an inventory/output pair and separate fact from evidence gaps."""

    asset = get_asset(bom, asset_ref)
    state = material_state(asset)
    associations = find_certificate_associations(bom, asset_ref)
    claim = _find_claim(approval, asset_ref)
    approval_schema = str((approval or {}).get("schema") or "")
    gaps: list[str] = []

    spec_version = str(bom.get("specVersion") or "")
    asset_type = crypto_properties(asset).get("assetType")
    if spec_version.startswith("1.6") and (
        asset_type == "certificate" or (asset_type == "related-crypto-material" and associations)
    ):
        gaps.append("cyclonedx-1.6:certificateState-1.7-omitted")

    if not associations and asset_type == "related-crypto-material":
        gaps.append("historical-certificate-association-missing")

    explicit_new_use: Optional[str] = None
    explicit_decision: Optional[str] = None
    evidence_refs: list[Any] = []
    if claim:
        permissions = claim.get("current_permissions") or claim.get("currentPermissions") or {}
        if isinstance(permissions, dict):
            value = permissions.get("new_use") or permissions.get("newUse")
            explicit_new_use = value if isinstance(value, str) else None
        decision_value = claim.get("decision")
        explicit_decision = decision_value if isinstance(decision_value, str) else None
        evidence_value = claim.get("evidence_refs") or claim.get("evidenceRefs")
        if isinstance(evidence_value, list):
            evidence_refs = evidence_value

    approval_evidence = bool((approval or {}).get("evidence"))
    if approval_schema.endswith("/v1") or (claim and not explicit_decision):
        gaps.append("approval-v1:extended-decision-field-omitted")
    if approval is not None and not approval_evidence:
        gaps.append("approval-output:evidence-block-missing")
    if claim is not None and not evidence_refs and not approval_evidence:
        gaps.append("approval-output:decision-evidence-link-missing")

    if explicit_new_use:
        new_use = explicit_new_use
    elif state == "deactivated":
        new_use = NewUsePermission.DENIED.value
    elif state == "active":
        new_use = NewUsePermission.PENDING.value
        gaps.append("inventory-state:active-does-not-prove-current-new-use-approval")
    else:
        new_use = NewUsePermission.PENDING.value
        gaps.append("inventory-state:missing-or-unsupported")

    if explicit_decision and approval_evidence:
        decision = explicit_decision
        confirmation = ConfirmationStatus.CONFIRMED.value
    else:
        decision = Decision.PENDING_CONFIRMATION.value
        confirmation = ConfirmationStatus.PENDING.value
        if state == RelatedState.DEACTIVATED.value and associations:
            gaps.append("decision-confirmation:pending-rich-approval-evidence")

    inventory_posture = classify_inventory_usage(bom, asset_ref)

    return {
        "asset_ref": asset_ref,
        "asset_name": asset_name(asset),
        "material_state": state,
        "inventory_usage_posture": inventory_posture,
        "reconstructed_usage_posture": inventory_posture,
        "current_new_use_permission": new_use,
        "decision": decision,
        "confirmation_status": confirmation,
        "historical_certificate_associations": associations,
        "historical_verification_relation": {
            "status": "confirmed" if associations else "missing",
            "certificate_refs": sorted({item["certificate_ref"] for item in associations}),
            "association_bases": sorted({item["basis"] for item in associations}),
        },
        "evidence_refs": evidence_refs,
        "evidence_gaps": gaps,
    }


def verify_name_scope_unchanged(
    before_bom: dict[str, Any], after_bom: dict[str, Any], refs: list[str]
) -> list[dict[str, Any]]:
    before = index_assets(before_bom)
    after = index_assets(after_bom)
    results = []
    for ref in refs:
        if ref not in before or ref not in after:
            raise AssetNotFoundError(f"namesake guard ref not found in both BOMs: {ref}")
        before_asset = before[ref]
        after_asset = after[ref]
        unchanged = canonical_digest(before_asset) == canonical_digest(after_asset)
        results.append(
            {
                "asset_ref": ref,
                "asset_name": asset_name(after_asset),
                "unchanged": unchanged,
                "before_state": material_state(before_asset),
                "after_state": material_state(after_asset),
            }
        )
    return results
