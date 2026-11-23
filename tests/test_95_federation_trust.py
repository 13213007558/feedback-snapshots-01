"""Acceptance tests for federation trust with static signatures plus MDQ.

The scenarios mirror the three acceptance phases:

1. dual-key rotation window - both keys verify, an explicit immutable trust
   view is used for in-flight verification;
2. retirement - a retired key is rejected and the decision survives an MDQ
   outage;
3. query failure - unaffected entities and the new key keep working while a
   directory failure, an explicit deletion and a fresh dual-key record never
   overwrite one another.

All signature material is generated locally with the ``cryptography``
library; no external xmlsec binary or network access is required.
"""

from xml.etree import ElementTree as ET

import pytest
import responses
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from saml2.federation import DS_NS
from saml2.federation import EntityDeleted
from saml2.federation import FederationError
from saml2.federation import FederationTrustResolver
from saml2.federation import KeyRetired
from saml2.federation import MdqClient
from saml2.federation import MdqOutcome
from saml2.federation import MdqQueryError
from saml2.federation import SignatureVerificationError
from saml2.federation import StaticTrustSource
from saml2.federation import TrustAnchorError
from saml2.federation import certificate_fingerprint
from saml2.federation import certificate_to_b64
from saml2.federation import generate_signing_material
from saml2.federation import sign_entity_descriptor
from saml2.federation import verify_metadata_signature

import requests


STATIC_ENTITY = "https://static.example/sp"
DYNAMIC_ENTITY = "https://dynamic.example/idp"
OTHER_ENTITY = "https://other.example/idp"
MDQ_BASE = "http://mdq.federation.test"


class FakeResponse:
    def __init__(self, status_code, content=b""):
        self.status_code = status_code
        self.content = content
        self.text = content.decode("utf-8") if isinstance(content, bytes) else content


def make_key(common_name):
    private_key, certificate = generate_signing_material(common_name=common_name)
    return {
        "key": private_key,
        "cert": certificate,
        "fp": certificate_fingerprint(certificate),
    }


def make_anchor():
    return make_key("federation-anchor")


def entity_descriptor_xml(entity_id, certificates):
    """Build an unsigned EntityDescriptor containing the given certs."""
    key_descriptors = []
    for certificate in certificates:
        key_descriptors.append(
            f"""<KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>
            <ds:X509Certificate>{certificate_to_b64(certificate)}</ds:X509Certificate>
            </ds:X509Data></ds:KeyInfo></KeyDescriptor>"""
        )
    xml = f"""<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
        xmlns:ds="{DS_NS}" entityID="{entity_id}">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        {''.join(key_descriptors)}
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="{entity_id}/sso"/>
        </IDPSSODescriptor></EntityDescriptor>"""
    return ET.fromstring(xml)


def signed_entity_record(entity_id, certificates, anchor):
    root = entity_descriptor_xml(entity_id, certificates)
    return sign_entity_descriptor(root, anchor["key"], anchor["cert"]).encode("utf-8")


def sign_payload(private_key, payload=b"challenge"):
    return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256()), payload


# ---------------------------------------------------------------------------
# Phase 1: dual-key window
# ---------------------------------------------------------------------------


def test_dual_key_window_accepts_both_keys():
    anchor = make_anchor()
    old_key = make_key("old-entity-key")
    new_key = make_key("new-entity-key")
    record = signed_entity_record(DYNAMIC_ENTITY, [old_key["cert"], new_key["cert"]], anchor)

    client = MdqClient(MDQ_BASE, {anchor["fp"]}, transport=lambda url: FakeResponse(200, record))
    resolver = FederationTrustResolver(mdq_client=client)

    view = resolver.trust_view(DYNAMIC_ENTITY)
    assert {key.fingerprint for key in view.active_keys} == {old_key["fp"], new_key["fp"]}

    signature, payload = sign_payload(old_key["key"])
    assert resolver.verify(DYNAMIC_ENTITY, old_key["fp"], signature, payload)
    signature, payload = sign_payload(new_key["key"])
    assert resolver.verify(DYNAMIC_ENTITY, new_key["fp"], signature, payload)


def test_inflight_view_is_explicit_and_immutable():
    anchor = make_anchor()
    old_key = make_key("old-entity-key")
    new_key = make_key("new-entity-key")
    record = signed_entity_record(DYNAMIC_ENTITY, [old_key["cert"], new_key["cert"]], anchor)
    client = MdqClient(MDQ_BASE, {anchor["fp"]}, transport=lambda url: FakeResponse(200, record))
    resolver = FederationTrustResolver(mdq_client=client)

    captured_view = resolver.trust_view(DYNAMIC_ENTITY)
    # Simulate an operator retiring the old key while the request is in flight.
    resolver.retire(DYNAMIC_ENTITY, old_key["fp"])

    signature, payload = sign_payload(old_key["key"])
    # The captured view still trusts the old key; the fresh view does not.
    assert FederationTrustResolver.verify_with_view(captured_view, old_key["fp"], signature, payload)
    with pytest.raises(KeyRetired):
        resolver.verify(DYNAMIC_ENTITY, old_key["fp"], signature, payload)


def test_dual_key_record_replaces_single_key_record():
    anchor = make_anchor()
    old_key = make_key("old-entity-key")
    new_key = make_key("new-entity-key")
    single = signed_entity_record(DYNAMIC_ENTITY, [old_key["cert"]], anchor)
    dual = signed_entity_record(DYNAMIC_ENTITY, [old_key["cert"], new_key["cert"]], anchor)

    responses_iter = iter([FakeResponse(200, single), FakeResponse(200, dual)])
    client = MdqClient(MDQ_BASE, {anchor["fp"]}, transport=lambda url: next(responses_iter))

    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.RECORD
    assert len(client.trust_view(DYNAMIC_ENTITY).active_keys) == 1
    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.RECORD
    assert len(client.trust_view(DYNAMIC_ENTITY).active_keys) == 2


# ---------------------------------------------------------------------------
# Phase 2: retirement
# ---------------------------------------------------------------------------


def test_retired_key_rejected_while_new_key_continues():
    anchor = make_anchor()
    old_key = make_key("old-entity-key")
    new_key = make_key("new-entity-key")
    record = signed_entity_record(DYNAMIC_ENTITY, [old_key["cert"], new_key["cert"]], anchor)
    client = MdqClient(MDQ_BASE, {anchor["fp"]}, transport=lambda url: FakeResponse(200, record))
    resolver = FederationTrustResolver(mdq_client=client)
    resolver.trust_view(DYNAMIC_ENTITY)

    resolver.retire(DYNAMIC_ENTITY, old_key["fp"])

    old_signature, payload = sign_payload(old_key["key"])
    with pytest.raises(KeyRetired):
        resolver.verify(DYNAMIC_ENTITY, old_key["fp"], old_signature, payload)
    new_signature, payload = sign_payload(new_key["key"])
    assert resolver.verify(DYNAMIC_ENTITY, new_key["fp"], new_signature, payload)


def test_retirement_survives_mdq_outage():
    anchor = make_anchor()
    old_key = make_key("old-entity-key")
    new_key = make_key("new-entity-key")
    record = signed_entity_record(DYNAMIC_ENTITY, [old_key["cert"], new_key["cert"]], anchor)

    calls = {"n": 0}

    def transport(url):
        calls["n"] += 1
        if calls["n"] == 1:
            return FakeResponse(200, record)
        raise requests.ConnectionError("network partition")

    client = MdqClient(MDQ_BASE, {anchor["fp"]}, transport=transport)
    resolver = FederationTrustResolver(mdq_client=client)
    resolver.trust_view(DYNAMIC_ENTITY)
    resolver.retire(DYNAMIC_ENTITY, old_key["fp"])

    outcome = client.query(DYNAMIC_ENTITY)
    assert outcome == MdqOutcome.UNAVAILABLE
    assert client.source_available is False

    old_signature, payload = sign_payload(old_key["key"])
    with pytest.raises(KeyRetired):
        resolver.verify(DYNAMIC_ENTITY, old_key["fp"], old_signature, payload)
    new_signature, payload = sign_payload(new_key["key"])
    assert resolver.verify(DYNAMIC_ENTITY, new_key["fp"], new_signature, payload)


def test_retirement_survives_outage_when_directory_republishes_old_key():
    anchor = make_anchor()
    old_key = make_key("old-entity-key")
    new_key = make_key("new-entity-key")
    record = signed_entity_record(DYNAMIC_ENTITY, [old_key["cert"], new_key["cert"]], anchor)
    # The directory wrongly re-publishes the retired key alongside the new one.
    republished = signed_entity_record(DYNAMIC_ENTITY, [old_key["cert"], new_key["cert"]], anchor)

    responses_iter = iter(
        [
            FakeResponse(200, record),
            FakeResponse(200, record),
            FakeResponse(200, republished),
        ]
    )
    client = MdqClient(MDQ_BASE, {anchor["fp"]}, transport=lambda url: next(responses_iter))
    resolver = FederationTrustResolver(mdq_client=client)
    resolver.trust_view(DYNAMIC_ENTITY)
    resolver.retire(DYNAMIC_ENTITY, old_key["fp"])

    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.RECORD
    view = resolver.trust_view(DYNAMIC_ENTITY)
    assert old_key["fp"] not in {key.fingerprint for key in view.active_keys}
    assert view.is_retired(old_key["fp"])


def test_new_requests_still_reject_retired_material_during_outage():
    anchor = make_anchor()
    old_key = make_key("old-entity-key")
    new_key = make_key("new-entity-key")
    record = signed_entity_record(DYNAMIC_ENTITY, [old_key["cert"], new_key["cert"]], anchor)

    calls = {"n": 0}

    def transport(url):
        calls["n"] += 1
        if calls["n"] == 1:
            return FakeResponse(200, record)
        raise requests.ConnectionError("network partition")

    client = MdqClient(MDQ_BASE, {anchor["fp"]}, transport=transport)
    resolver = FederationTrustResolver(mdq_client=client)
    resolver.trust_view(DYNAMIC_ENTITY)
    resolver.retire(DYNAMIC_ENTITY, old_key["fp"])

    old_signature, payload = sign_payload(old_key["key"])
    new_signature, _ = sign_payload(new_key["key"])
    # Every fresh request during the outage re-runs the query, which fails,
    # yet the retirement decision is still enforced.
    for _ in range(3):
        with pytest.raises(KeyRetired):
            resolver.verify(DYNAMIC_ENTITY, old_key["fp"], old_signature, payload)
        assert resolver.verify(DYNAMIC_ENTITY, new_key["fp"], new_signature, payload)


def test_static_retirement_survives_outage():
    anchor = make_anchor()
    entity_key = make_key("static-entity-key")
    record = signed_entity_record(STATIC_ENTITY, [entity_key["cert"]], anchor)
    static = StaticTrustSource("static-file", record, {anchor["fp"]})
    resolver = FederationTrustResolver(static_sources=[static])

    resolver.retire(STATIC_ENTITY, entity_key["fp"])
    signature, payload = sign_payload(entity_key["key"])
    with pytest.raises(KeyRetired):
        resolver.verify(STATIC_ENTITY, entity_key["fp"], signature, payload)
    # Static entities never touch the network, so there is nothing to recover
    # from; the retirement remains authoritative for every later request.
    with pytest.raises(KeyRetired):
        resolver.verify(STATIC_ENTITY, entity_key["fp"], signature, payload)


# ---------------------------------------------------------------------------
# Phase 3: query failures, deletions and fresh records do not overwrite each
# other
# ---------------------------------------------------------------------------


def test_unavailable_keeps_last_record_and_unaffected_entities_serve():
    anchor = make_anchor()
    dynamic_key = make_key("dynamic-key")
    other_key = make_key("other-key")
    dynamic_record = signed_entity_record(DYNAMIC_ENTITY, [dynamic_key["cert"]], anchor)
    other_record = signed_entity_record(OTHER_ENTITY, [other_key["cert"]], anchor)

    client = MdqClient(MDQ_BASE, {anchor["fp"]})
    dynamic_url = client._entity_url(DYNAMIC_ENTITY)
    other_url = client._entity_url(OTHER_ENTITY)
    dynamic_calls = {"n": 0}

    def transport(url):
        if url == dynamic_url:
            dynamic_calls["n"] += 1
            if dynamic_calls["n"] >= 2:
                raise requests.Timeout("short network fault")
            return FakeResponse(200, dynamic_record)
        if url == other_url:
            return FakeResponse(200, other_record)
        raise requests.ConnectionError("unknown entity")

    client.transport = transport
    resolver = FederationTrustResolver(mdq_client=client)

    resolver.trust_view(DYNAMIC_ENTITY)
    assert client.query(OTHER_ENTITY) == MdqOutcome.RECORD

    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.UNAVAILABLE
    # Last good record is still served for the affected entity.
    view = resolver.trust_view(DYNAMIC_ENTITY)
    assert view.is_trusted(dynamic_key["fp"])
    signature, payload = sign_payload(dynamic_key["key"])
    assert resolver.verify(DYNAMIC_ENTITY, dynamic_key["fp"], signature, payload)

    # Unaffected entity still verifies normally.
    signature, payload = sign_payload(other_key["key"])
    assert resolver.verify(OTHER_ENTITY, other_key["fp"], signature, payload)


def test_explicit_deletion_is_a_tombstone_that_survives_outage():
    anchor = make_anchor()
    entity_key = make_key("doomed-key")
    record = signed_entity_record(DYNAMIC_ENTITY, [entity_key["cert"]], anchor)

    sequence = iter(
        [
            FakeResponse(200, record),
            FakeResponse(404),
        ]
    )

    def transport(url):
        try:
            return next(sequence)
        except StopIteration:
            raise requests.ConnectionError("network down after deletion")

    client = MdqClient(MDQ_BASE, {anchor["fp"]}, transport=transport)
    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.RECORD
    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.DELETED

    # A later outage must not resurrect the deleted entity.
    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.UNAVAILABLE
    assert client._cache[DYNAMIC_ENTITY].state == MdqOutcome.DELETED
    with pytest.raises(EntityDeleted):
        client.trust_view(DYNAMIC_ENTITY)


def test_fresh_record_after_outage_restores_service():
    anchor = make_anchor()
    old_key = make_key("old-key")
    new_key = make_key("new-key")
    record = signed_entity_record(DYNAMIC_ENTITY, [old_key["cert"]], anchor)
    dual = signed_entity_record(DYNAMIC_ENTITY, [old_key["cert"], new_key["cert"]], anchor)

    sequence = iter(
        [
            FakeResponse(200, record),
            FakeResponse(503),
            FakeResponse(200, dual),
        ]
    )
    client = MdqClient(
        MDQ_BASE,
        {anchor["fp"]},
        transport=lambda url: next(sequence),
    )

    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.RECORD
    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.UNAVAILABLE
    # The outage preserved the prior record.
    assert len(client.trust_view(DYNAMIC_ENTITY).active_keys) == 1
    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.RECORD
    assert len(client.trust_view(DYNAMIC_ENTITY).active_keys) == 2


def test_fresh_record_revives_a_tombstone_but_outage_does_not():
    anchor = make_anchor()
    entity_key = make_key("entity-key")
    record = signed_entity_record(DYNAMIC_ENTITY, [entity_key["cert"]], anchor)
    sequence = iter(
        [
            FakeResponse(200, record),
            FakeResponse(404),
            FakeResponse(503),
            FakeResponse(200, record),
        ]
    )
    client = MdqClient(MDQ_BASE, {anchor["fp"]}, transport=lambda url: next(sequence))

    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.RECORD
    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.DELETED
    # Outage preserves the tombstone rather than resurrecting the entity.
    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.UNAVAILABLE
    assert client._cache[DYNAMIC_ENTITY].state == MdqOutcome.DELETED
    # An authoritative fresh record is allowed to replace the tombstone.
    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.RECORD
    assert client.trust_view(DYNAMIC_ENTITY).is_trusted(entity_key["fp"])


def test_first_contact_outage_has_no_state_to_revive():
    anchor = make_anchor()
    client = MdqClient(
        MDQ_BASE,
        {anchor["fp"]},
        transport=lambda url: (_ for _ in ()).throw(requests.ConnectionError("down")),
    )
    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.UNAVAILABLE
    with pytest.raises(MdqQueryError):
        client.trust_view(DYNAMIC_ENTITY)


# ---------------------------------------------------------------------------
# Signature integrity and trust anchors
# ---------------------------------------------------------------------------


def test_unsigned_and_tampered_records_are_rejected():
    anchor = make_anchor()
    entity_key = make_key("entity-key")
    record = signed_entity_record(DYNAMIC_ENTITY, [entity_key["cert"]], anchor)

    unsigned = entity_descriptor_xml(DYNAMIC_ENTITY, [entity_key["cert"]])
    client = MdqClient(
        MDQ_BASE,
        {anchor["fp"]},
        transport=lambda url: FakeResponse(200, ET.tostring(unsigned)),
    )
    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.UNAVAILABLE

    tampered = record.replace(b"/sso", b"/tampered-sso")
    client = MdqClient(MDQ_BASE, {anchor["fp"]}, transport=lambda url: FakeResponse(200, tampered))
    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.UNAVAILABLE
    with pytest.raises(MdqQueryError):
        client.trust_view(DYNAMIC_ENTITY)


def test_untrusted_signer_is_rejected():
    anchor = make_anchor()
    rogue_anchor = make_key("rogue-anchor")
    entity_key = make_key("entity-key")
    record = signed_entity_record(DYNAMIC_ENTITY, [entity_key["cert"]], rogue_anchor)
    with pytest.raises(TrustAnchorError):
        verify_metadata_signature(record, {anchor["fp"]})

    client = MdqClient(MDQ_BASE, {anchor["fp"]}, transport=lambda url: FakeResponse(200, record))
    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.UNAVAILABLE


def test_static_source_requires_valid_anchor():
    anchor = make_anchor()
    entity_key = make_key("entity-key")
    record = signed_entity_record(STATIC_ENTITY, [entity_key["cert"]], anchor)
    with pytest.raises(TrustAnchorError):
        StaticTrustSource("static-file", record, {"00" * 32})
    static = StaticTrustSource("static-file", record, {anchor["fp"]})
    assert static.trust_view(STATIC_ENTITY).is_trusted(entity_key["fp"])


def test_unknown_fingerprint_fails_verification():
    anchor = make_anchor()
    entity_key = make_key("entity-key")
    record = signed_entity_record(DYNAMIC_ENTITY, [entity_key["cert"]], anchor)
    client = MdqClient(MDQ_BASE, {anchor["fp"]}, transport=lambda url: FakeResponse(200, record))
    resolver = FederationTrustResolver(mdq_client=client)
    resolver.trust_view(DYNAMIC_ENTITY)
    signature, payload = sign_payload(entity_key["key"])
    with pytest.raises(FederationError):
        resolver.verify(DYNAMIC_ENTITY, "ab" * 32, signature, payload)


def test_bad_payload_signature_fails():
    anchor = make_anchor()
    entity_key = make_key("entity-key")
    record = signed_entity_record(DYNAMIC_ENTITY, [entity_key["cert"]], anchor)
    client = MdqClient(MDQ_BASE, {anchor["fp"]}, transport=lambda url: FakeResponse(200, record))
    resolver = FederationTrustResolver(mdq_client=client)
    resolver.trust_view(DYNAMIC_ENTITY)
    signature, _ = sign_payload(entity_key["key"])
    with pytest.raises(SignatureVerificationError):
        resolver.verify(DYNAMIC_ENTITY, entity_key["fp"], signature, b"different payload")


def test_signer_anchor_cert_is_not_treated_as_entity_key():
    anchor = make_anchor()
    entity_key = make_key("entity-key")
    record = signed_entity_record(DYNAMIC_ENTITY, [entity_key["cert"]], anchor)

    client = MdqClient(MDQ_BASE, {anchor["fp"]}, transport=lambda url: FakeResponse(200, record))
    client.query(DYNAMIC_ENTITY)
    fingerprints = {key.fingerprint for key in client.trust_view(DYNAMIC_ENTITY).active_keys}
    assert fingerprints == {entity_key["fp"]}
    assert anchor["fp"] not in fingerprints


def test_static_source_construction_time_retirement_is_entity_scoped():
    anchor = make_anchor()
    retired_key = make_key("retired-key")
    healthy_key = make_key("healthy-key")
    record = signed_entity_record(STATIC_ENTITY, [retired_key["cert"], healthy_key["cert"]], anchor)
    static = StaticTrustSource(
        "static-file",
        record,
        {anchor["fp"]},
        retired_fingerprints={STATIC_ENTITY: {retired_key["fp"]}},
    )
    view = static.trust_view(STATIC_ENTITY)
    assert view.is_retired(retired_key["fp"])
    assert view.is_trusted(healthy_key["fp"])


@responses.activate
def test_mdq_client_works_against_mocked_http():
    anchor = make_anchor()
    entity_key = make_key("entity-key")
    record = signed_entity_record(DYNAMIC_ENTITY, [entity_key["cert"]], anchor)
    import hashlib
    from urllib.parse import quote

    transform = "{sha1}" + hashlib.sha1(DYNAMIC_ENTITY.encode("utf-8")).hexdigest()
    url = f"{MDQ_BASE}/entities/{quote(transform)}"
    responses.add(
        responses.GET,
        url,
        body=record,
        status=200,
        content_type="application/samlmetadata+xml",
    )
    client = MdqClient(MDQ_BASE, {anchor["fp"]})
    assert client.query(DYNAMIC_ENTITY) == MdqOutcome.RECORD
    assert client.trust_view(DYNAMIC_ENTITY).is_trusted(entity_key["fp"])
    assert len(responses.calls) == 1
