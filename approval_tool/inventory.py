"""Fictional CycloneDX inventory used by the key-rotation scenario."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, cast
from uuid import NAMESPACE_URL, uuid5

from cyclonedx.model import Property, XsUri
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    CertificateProperties,
    CryptoAssetType,
    CryptoProperties,
    RelatedCryptoMaterialState,
    RelatedCryptoMaterialProperties,
    RelatedCryptoMaterialType,
)
from cyclonedx.model.service import Service
from cyclonedx.output.json import JsonV1Dot7

from .core import NAMESPACE


ROTATION_ID = "ROT-20261126-001"
FIXED_TIMESTAMP = datetime(2026, 11, 26, 9, 0, tzinfo=timezone.utc)
APPROVED_TIMESTAMP = "2026-11-26T10:00:00Z"

CHECKOUT_SERVICE_REF = "service:checkout-api"
CATALOG_SERVICE_REF = "service:catalog-search-api"
OLD_KEY_REF = "asset:key:checkout-signing-2024q1"
NEW_KEY_REF = "asset:key:checkout-signing-2026q4"
OLD_CERT_REF = "asset:cert:checkout-signing-2024q1"
NEW_CERT_REF = "asset:cert:checkout-signing-2026q4"
NAMESAKE_KEY_REF = "asset:key:catalog-search-index-2024q4"
SHARED_KEY_NAME = "checkout-signing-key"
SHARED_CERT_NAME = "checkout-signing-certificate"


def fictional_fingerprint(asset_ref: str) -> str:
    import hashlib

    return hashlib.sha256(("fictional:" + asset_ref).encode("utf-8")).hexdigest()


def _key_component(
    *,
    ref: str,
    name: str,
    state: RelatedCryptoMaterialState,
    service_ref: str,
    purpose: str,
    description: str,
) -> Component:
    return Component(
        bom_ref=ref,
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        name=name,
        version="fictional",
        description=description,
        properties=[
            Property(name=f"{NAMESPACE}/service-ref", value=service_ref),
            Property(name=f"{NAMESPACE}/purpose", value=purpose),
            Property(name=f"{NAMESPACE}/fictional-fingerprint-sha256", value=fictional_fingerprint(ref)),
        ],
        crypto_properties=CryptoProperties(
            asset_type=CryptoAssetType.RELATED_CRYPTO_MATERIAL,
            related_crypto_material_properties=RelatedCryptoMaterialProperties(
                type=RelatedCryptoMaterialType.PUBLIC_KEY,
                state=state,
                id=ref,
            ),
        ),
    )


def _certificate_component(
    *,
    ref: str,
    key_ref: str,
    common_name: str,
    not_before: datetime,
    not_after: datetime,
    description: str,
) -> Component:
    return Component(
        bom_ref=ref,
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        name=SHARED_CERT_NAME,
        version="fictional",
        description=description,
        properties=[
            Property(name=f"{NAMESPACE}/common-name", value=common_name),
            Property(name=f"{NAMESPACE}/fictional-certificate", value="true"),
        ],
        crypto_properties=CryptoProperties(
            asset_type=CryptoAssetType.CERTIFICATE,
            certificate_properties=CertificateProperties(
                subject_name=f"CN={common_name}, O=Fictional Payments",
                issuer_name="CN=Fictional Rotation CA, O=Fictional Example",
                not_valid_before=not_before,
                not_valid_after=not_after,
                certificate_format="X.509",
                certificate_extension="crt",
                subject_public_key_ref=BomRef(key_ref),
            ),
        ),
    )


def build_pre_rotation_bom() -> Bom:
    serial = uuid5(NAMESPACE_URL, f"https://approval.example/key-rotation/{ROTATION_ID}/bom")
    bom = Bom(
        serial_number=serial,
        version=1,
        metadata=BomMetaData(
            timestamp=FIXED_TIMESTAMP,
            component=Component(
                bom_ref="app:checkout-service",
                type=ComponentType.APPLICATION,
                name="fictional-checkout-service",
                version="2026.11",
                description="Fictional service that signs receipts and verifies historical signatures.",
            ),
            properties=[
                Property(name=f"{NAMESPACE}/scenario", value="certificate-key-rotation"),
                Property(name=f"{NAMESPACE}/rotation-id", value=ROTATION_ID),
            ],
        ),
    )

    old_key = _key_component(
        ref=OLD_KEY_REF,
        name=SHARED_KEY_NAME,
        state=RelatedCryptoMaterialState.ACTIVE,
        service_ref=CHECKOUT_SERVICE_REF,
        purpose="payment-receipt-signature",
        description="Old fictional key. Before approval it is still active; after rotation it verifies history only.",
    )
    new_key = _key_component(
        ref=NEW_KEY_REF,
        name=SHARED_KEY_NAME,
        state=RelatedCryptoMaterialState.PRE_ACTIVATION,
        service_ref=CHECKOUT_SERVICE_REF,
        purpose="payment-receipt-signature",
        description="Replacement fictional key waiting for approved activation.",
    )
    namesake_key = _key_component(
        ref=NAMESAKE_KEY_REF,
        name=SHARED_KEY_NAME,
        state=RelatedCryptoMaterialState.ACTIVE,
        service_ref=CATALOG_SERVICE_REF,
        purpose="search-index-signature",
        description="Unrelated namesake asset used to prove updates are bom-ref scoped.",
    )

    old_cert = _certificate_component(
        ref=OLD_CERT_REF,
        key_ref=OLD_KEY_REF,
        common_name="checkout-signing-2024q1",
        not_before=datetime(2024, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        description="Old fictional certificate retained for historical signature verification.",
    )
    new_cert = _certificate_component(
        ref=NEW_CERT_REF,
        key_ref=NEW_KEY_REF,
        common_name="checkout-signing-2026q4",
        not_before=datetime(2026, 11, 26, tzinfo=timezone.utc),
        not_after=datetime(2028, 11, 26, tzinfo=timezone.utc),
        description="New fictional certificate approved for new signatures.",
    )

    for component in (old_key, new_key, namesake_key, old_cert, new_cert):
        bom.components.add(component)

    checkout_service = Service(
        bom_ref=CHECKOUT_SERVICE_REF,
        name="checkout-api",
        version="fictional",
        description="Fictional payment receipt signing service.",
        endpoints=[XsUri("https://checkout.example.invalid/rpc")],
        properties=[Property(name=f"{NAMESPACE}/handles-historical-signatures", value="true")],
    )
    catalog_service = Service(
        bom_ref=CATALOG_SERVICE_REF,
        name="catalog-search-api",
        version="fictional",
        description="Unrelated service with a same-named key material.",
    )
    bom.services.add(checkout_service)
    bom.services.add(catalog_service)

    bom.register_dependency(checkout_service, [old_key, new_key, old_cert, new_cert])
    bom.register_dependency(catalog_service, [namesake_key])
    if bom.metadata.component is not None:
        bom.register_dependency(bom.metadata.component, [checkout_service, catalog_service])
    return bom


def build_pre_rotation_bom_dict() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(JsonV1Dot7(build_pre_rotation_bom()).output_as_string()))


def build_rotation_request() -> dict[str, Any]:
    from .core import REQUEST_V1_SCHEMA

    return {
        "$schema": REQUEST_V1_SCHEMA,
        "schema": "key-rotation-request/v1",
        "rotation_id": ROTATION_ID,
        "status": "approved",
        "decision": "approved",
        "submitted_at": FIXED_TIMESTAMP.isoformat().replace("+00:00", "Z"),
        "approved_at": APPROVED_TIMESTAMP,
        "approved_by": "Fictional Key Rotation Approval Board <approvals@example.invalid>",
        "service_ref": CHECKOUT_SERVICE_REF,
        "old_asset_ref": OLD_KEY_REF,
        "new_asset_ref": NEW_KEY_REF,
        "namesake_guard_refs": [NAMESAKE_KEY_REF],
        "requested_effect": {
            OLD_KEY_REF: "withdraw-new-use-and-retain-historical-verification",
            NEW_KEY_REF: "allow-new-use",
        },
        "ticket": "FB-20261120-SEC7558-190-FICTION",
    }
