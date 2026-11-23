"""Federation trust management with static signatures and on-demand MDQ.

This module implements the trust model used when a deployment combines
entities from a statically signed metadata file with entities discovered
through an MDQ (per-entity metadata query, RFC 8415 style) service.

Design goals, derived from the operational requirements:

* A *retirement* decision is durable. Once a signing key has been retired it
  stays rejected even if a later MDQ query fails (network partition, timeout,
  5xx). A failed query can never resurrect a retired key.
* A key *rotation* runs inside an explicit dual-key window: both the old and
  the new key are trusted simultaneously, and each verification uses an
  immutable snapshot ("trust view") of the keys valid for that request.
* The three observable MDQ outcomes are distinct and never overwrite one
  another:

  =========================================== =================================
  Outcome                                     Cache effect
  =========================================== =================================
  query failure (network/timeout/5xx)         keep the previous authoritative
                                              state, mark the source as
                                              unavailable
  explicit deletion (HTTP 404)                record a tombstone
  fresh signed record (HTTP 200)              replace the state, including a
                                              legitimate dual-key record
  =========================================== =================================

The module only depends on the standard library and ``cryptography`` so that
signature material can be generated and verified locally without an external
xmlsec binary.
"""

import base64
import copy
import enum
import hashlib
import hmac
import logging
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from xml.etree import ElementTree as ET

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import defusedxml.ElementTree

from saml2 import SAMLError


logger = logging.getLogger(__name__)

DS_NS = "http://www.w3.org/2000/09/xmldsig#"
MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"

CANONICAL_XML_1_1 = "http://www.w3.org/2006/12/xml-c14n11"
ENVELOPED_SIGNATURE = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
RSA_SHA256 = "http://www.w3.org/2000/09/xmldsig#rsa-sha256"
SHA256 = "http://www.w3.org/2000/09/xmldsig#sha256"

SAML_METADATA_CONTENT_TYPE = "application/samlmetadata+xml"


class FederationError(SAMLError):
    """Base class for federation trust errors."""


class SignatureVerificationError(FederationError):
    """Raised when a metadata signature cannot be verified against an anchor."""


class TrustAnchorError(FederationError):
    """Raised when a metadata signer is not covered by the configured anchors."""


class MdqQueryError(FederationError):
    """Raised when an MDQ query fails and no cached state can be served."""


class EntityDeleted(FederationError):
    """Raised when an MDQ directory has explicitly deleted an entity."""


class KeyRetired(FederationError):
    """Raised when verification is attempted with a retired key."""


def _q(ns, tag):
    return f"{{{ns}}}{tag}"


def canonical_xml(element):
    """Return the canonical byte representation of an element.

    The standard library exposes C14N 2.0 through ``ElementTree.canonicalize``.
    Both signature production and verification in this module call this exact
    helper and advertise :data:`CANONICAL_XML_1_1`, so produced documents are
    always self-consistent, independently of any external xmlsec binary.
    """
    serialized = ET.tostring(element)
    return ET.canonicalize(serialized, with_comments=False).encode("utf-8")


def certificate_fingerprint(certificate):
    """Return the SHA-256 fingerprint (lower-case hex) of a certificate."""
    return certificate.fingerprint(hashes.SHA256()).hex()


def certificate_to_b64(certificate):
    """Return the base-64 DER payload of a certificate without PEM armour."""
    pem = certificate.public_bytes(serialization.Encoding.PEM)
    return "".join(pem.decode("utf-8").splitlines()[1:-1])


def certificate_from_b64(b64_text):
    """Load a certificate from a bare base-64 DER string."""
    pem = "-----BEGIN CERTIFICATE-----\n" + b64_text.strip() + "\n-----END CERTIFICATE-----"
    return x509.load_pem_x509_certificate(pem.encode("utf-8"))


def generate_signing_material(common_name="federation-test-entity", key_size=2048, days_valid=3650):
    """Generate a local RSA private key and a self-signed signing certificate.

    Intended for tests and local acceptance material; nothing here requires
    network access.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
        .sign(private_key, hashes.SHA256())
    )
    return private_key, certificate


def _find_direct_child(element, ns, tag):
    return element.find(_q(ns, tag))


def sign_entity_descriptor(entity_root, private_key, signer_certificate):
    """Add an enveloped XML signature to an EntityDescriptor element tree.

    The signature covers the whole descriptor with an enveloped-signature
    transform. The signed document is returned as text.
    """
    root = copy.deepcopy(entity_root)
    signature = ET.SubElement(root, _q(DS_NS, "Signature"))

    signed_info = ET.SubElement(signature, _q(DS_NS, "SignedInfo"))
    ET.SubElement(signed_info, _q(DS_NS, "CanonicalizationMethod"), Algorithm=CANONICAL_XML_1_1)
    ET.SubElement(signed_info, _q(DS_NS, "SignatureMethod"), Algorithm=RSA_SHA256)

    reference = ET.SubElement(signed_info, _q(DS_NS, "Reference"), URI="")
    transforms = ET.SubElement(reference, _q(DS_NS, "Transforms"))
    ET.SubElement(transforms, _q(DS_NS, "Transform"), Algorithm=ENVELOPED_SIGNATURE)
    ET.SubElement(transforms, _q(DS_NS, "Transform"), Algorithm=CANONICAL_XML_1_1)
    ET.SubElement(reference, _q(DS_NS, "DigestMethod"), Algorithm=SHA256)
    digest_value = ET.SubElement(reference, _q(DS_NS, "DigestValue"))

    signature_value = ET.SubElement(signature, _q(DS_NS, "SignatureValue"))
    key_info = ET.SubElement(signature, _q(DS_NS, "KeyInfo"))
    x509_data = ET.SubElement(key_info, _q(DS_NS, "X509Data"))
    x509_certificate = ET.SubElement(x509_data, _q(DS_NS, "X509Certificate"))
    x509_certificate.text = certificate_to_b64(signer_certificate)

    unsigned_root = copy.deepcopy(root)
    unsigned_root.remove(_find_direct_child(unsigned_root, DS_NS, "Signature"))
    digest = hashlib.sha256(canonical_xml(unsigned_root)).digest()
    digest_value.text = base64.b64encode(digest).decode("ascii")

    raw_signature = private_key.sign(canonical_xml(signed_info), padding.PKCS1v15(), hashes.SHA256())
    signature_value.text = base64.b64encode(raw_signature).decode("ascii")
    return ET.tostring(root, encoding="unicode")


def _verify_signed_info(signed_info, signature_value, public_key):
    try:
        public_key.verify(
            base64.b64decode(signature_value.text.strip()),
            canonical_xml(signed_info),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise SignatureVerificationError("XML signature value does not verify") from exc


def _verify_reference(reference, root, signature):
    digest_method = _find_direct_child(reference, DS_NS, "DigestMethod")
    if digest_method is None or digest_method.get("Algorithm") != SHA256:
        raise SignatureVerificationError("Unsupported or missing digest algorithm")
    transforms = _find_direct_child(reference, DS_NS, "Transforms")
    allowed = {ENVELOPED_SIGNATURE, CANONICAL_XML_1_1}
    if transforms is None:
        observed = set()
    else:
        observed = {node.get("Algorithm") for node in transforms.findall(_q(DS_NS, "Transform"))}
    if ENVELOPED_SIGNATURE not in observed or not observed.issubset(allowed):
        raise SignatureVerificationError("Reference uses disallowed transforms")

    unsigned_root = copy.deepcopy(root)
    unsigned_signature = _find_direct_child(unsigned_root, DS_NS, "Signature")
    unsigned_root.remove(unsigned_signature)
    expected = base64.b64encode(hashlib.sha256(canonical_xml(unsigned_root)).digest()).decode("ascii")
    actual = _find_direct_child(reference, DS_NS, "DigestValue").text.strip()
    if not _constant_time_equal(expected, actual):
        raise SignatureVerificationError("Reference digest does not match the signed content")


def _constant_time_equal(a, b):
    return hmac.compare_digest(a.encode("ascii"), b.encode("ascii"))


def verify_metadata_signature(xml_text, trusted_fingerprints):
    """Verify an enveloped signature and return the signer's certificate.

    :param xml_text: signed EntityDescriptor/EntitiesDescriptor document
    :param trusted_fingerprints: set of SHA-256 fingerprints that are allowed
        to sign metadata. A document signed by anything else is rejected.
    :return: the verified signer ``x509.Certificate``
    """
    root = defusedxml.ElementTree.fromstring(xml_text)
    signature = _find_direct_child(root, DS_NS, "Signature")
    if signature is None:
        raise SignatureVerificationError("Metadata document is not signed")

    signed_info = _find_direct_child(signature, DS_NS, "SignedInfo")
    if signed_info is None:
        raise SignatureVerificationError("Signature missing SignedInfo")
    signature_method = _find_direct_child(signed_info, DS_NS, "SignatureMethod")
    if signature_method is None or signature_method.get("Algorithm") != RSA_SHA256:
        raise SignatureVerificationError("Unsupported or missing signature algorithm")

    reference = signed_info.find(_q(DS_NS, "Reference"))
    if reference is None or reference.get("URI") not in ("", None):
        raise SignatureVerificationError("Only whole-document empty-URI references are accepted")
    _verify_reference(reference, root, signature)

    cert_node = signature.iter(_q(DS_NS, "X509Certificate"))
    cert_node = next(cert_node, None)
    if cert_node is None or not (cert_node.text or "").strip():
        raise SignatureVerificationError("Signature does not embed an X.509 certificate")
    signer_certificate = certificate_from_b64(cert_node.text)
    fingerprint = certificate_fingerprint(signer_certificate)
    if fingerprint not in trusted_fingerprints:
        raise TrustAnchorError(f"Signer {fingerprint} is not a trusted metadata anchor")

    signature_value = _find_direct_child(signature, DS_NS, "SignatureValue")
    _verify_signed_info(signed_info, signature_value, signer_certificate.public_key())
    return signer_certificate


@dataclass(frozen=True)
class KeyMaterial:
    """An immutable view of one trusted signing key."""

    fingerprint: str
    certificate_b64: str
    public_key: object = field(compare=False)
    retired: bool = False

    @property
    def is_active(self):
        return not self.retired


@dataclass(frozen=True)
class TrustView:
    """Immutable snapshot of the keys trusted for one verification request."""

    entity_id: str
    active_keys: frozenset = field(default_factory=frozenset)
    retired_keys: frozenset = field(default_factory=frozenset)
    source: str = ""
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_trusted(self, fingerprint):
        return any(key.fingerprint == fingerprint for key in self.active_keys)

    def is_retired(self, fingerprint):
        return any(key.fingerprint == fingerprint for key in self.retired_keys)


class MdqOutcome(enum.Enum):
    """The three distinct outcomes an MDQ query can have."""

    RECORD = "record"
    DELETED = "deleted"
    UNAVAILABLE = "unavailable"


@dataclass
class _CacheEntry:
    entity_id: str
    state: MdqOutcome
    active_keys: dict = field(default_factory=dict)
    retired_keys: dict = field(default_factory=dict)
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "mdq"

    def trust_view(self):
        return TrustView(
            entity_id=self.entity_id,
            active_keys=frozenset(self.active_keys.values()),
            retired_keys=frozenset(self.retired_keys.values()),
            source=self.source,
        )


def parse_entity_keys(xml_text):
    """Extract signing-key certificates from an EntityDescriptor document.

    Returns a tuple ``(entity_id, certificates)`` where certificates are
    ``x509.Certificate`` instances found in signing KeyDescriptor elements.
    KeyDescriptors without an explicit use are treated as signing capable.
    """
    root = defusedxml.ElementTree.fromstring(xml_text)
    if root.tag != _q(MD_NS, "EntityDescriptor"):
        raise FederationError("MDQ responses must contain a single EntityDescriptor")
    entity_id = root.get("entityID")
    if not entity_id:
        raise FederationError("EntityDescriptor missing entityID")

    certificates = []
    for key_descriptor in root.iter(_q(MD_NS, "KeyDescriptor")):
        use = key_descriptor.get("use")
        if use not in (None, "signing"):
            continue
        key_info = key_descriptor.find(_q(DS_NS, "KeyInfo"))
        if key_info is None:
            continue
        for cert_node in key_info.iter(_q(DS_NS, "X509Certificate")):
            if cert_node.text and cert_node.text.strip():
                certificates.append(certificate_from_b64(cert_node.text))
    return entity_id, certificates


def _key_from_certificate(certificate, retired=False):
    return KeyMaterial(
        fingerprint=certificate_fingerprint(certificate),
        certificate_b64=certificate_to_b64(certificate),
        public_key=certificate.public_key(),
        retired=retired,
    )


class StaticTrustSource:
    """Trust source backed by a locally stored, signed metadata document.

    The document signature is verified once against the configured anchor
    fingerprints. Retired keys are supplied explicitly by the operator; they
    live outside the signed document so that a retirement survives any later
    inability to reach remote sources.
    """

    def __init__(self, name, xml_text, trusted_fingerprints, retired_fingerprints=None):
        self.name = name
        self.trusted_fingerprints = set(trusted_fingerprints)
        # Retirements are scoped per entity: ``{"entity_id": {fp1, fp2}}``.
        self.retired_fingerprints = {
            entity_id: set(fingerprints) for entity_id, fingerprints in (retired_fingerprints or {}).items()
        }
        verify_metadata_signature(xml_text, self.trusted_fingerprints)

        root = defusedxml.ElementTree.fromstring(xml_text)
        descriptors = root.iter(_q(MD_NS, "EntityDescriptor"))
        self._entities = {}
        for descriptor in descriptors:
            entity_id = descriptor.get("entityID")
            if not entity_id:
                continue
            entity_xml = ET.tostring(descriptor, encoding="unicode")
            _, certificates = parse_entity_keys(entity_xml)
            entity_retirements = self.retired_fingerprints.get(entity_id, set())
            active = {}
            retired = {}
            for certificate in certificates:
                material = _key_from_certificate(
                    certificate, retired=certificate_fingerprint(certificate) in entity_retirements
                )
                if material.retired:
                    retired[material.fingerprint] = material
                else:
                    active[material.fingerprint] = material
            # Operator-declared retirements may name keys no longer present in
            # the document; keep them so they remain rejected during outages.
            for fingerprint in entity_retirements:
                if fingerprint not in retired:
                    retired[fingerprint] = KeyMaterial(
                        fingerprint=fingerprint,
                        certificate_b64="",
                        public_key=None,
                        retired=True,
                    )
            self._entities[entity_id] = TrustView(
                entity_id=entity_id,
                active_keys=frozenset(active.values()),
                retired_keys=frozenset(retired.values()),
                source=name,
            )

    def entity_ids(self):
        return set(self._entities)

    def trust_view(self, entity_id):
        return self._entities.get(entity_id)

    def retire(self, entity_id, fingerprint):
        """Record an operator-confirmed retirement for a static entity."""
        view = self._entities.get(entity_id)
        if view is None:
            raise FederationError(f"Unknown static entity {entity_id}")
        active = {key.fingerprint: key for key in view.active_keys if key.fingerprint != fingerprint}
        retired = {key.fingerprint: key for key in view.retired_keys}
        moved = next((key for key in view.active_keys if key.fingerprint == fingerprint), None)
        if moved is not None:
            retired[fingerprint] = KeyMaterial(
                fingerprint=moved.fingerprint,
                certificate_b64=moved.certificate_b64,
                public_key=moved.public_key,
                retired=True,
            )
        else:
            retired[fingerprint] = KeyMaterial(
                fingerprint=fingerprint, certificate_b64="", public_key=None, retired=True
            )
        self._entities[entity_id] = TrustView(
            entity_id=entity_id,
            active_keys=frozenset(active.values()),
            retired_keys=frozenset(retired.values()),
            source=view.source,
        )


class MdqClient:
    """Stateful MDQ client with explicit state transitions.

    The cache stores one :class:`_CacheEntry` per entity. The transition rules
    guarantee that the three query outcomes cannot overwrite one another:

    * ``UNAVAILABLE`` never mutates an existing entry (it only flips the
      source-available flag), so retirements and tombstones survive outages.
    * ``DELETED`` writes a tombstone that an outage cannot remove.
    * ``RECORD`` replaces the entry atomically with the freshly verified
      record, which may legitimately contain two active keys.
    """

    def __init__(self, base_url, trusted_fingerprints, timeout=None, transport=None):
        self.base_url = base_url.rstrip("/")
        self.trusted_fingerprints = set(trusted_fingerprints)
        self.timeout = timeout
        self.transport = transport
        self._cache = {}
        self.source_available = True

    def _entity_url(self, entity_id):
        from urllib.parse import quote

        transform = "{sha1}" + hashlib.sha1(entity_id.encode("utf-8")).hexdigest()
        return f"{self.base_url}/entities/{quote(transform)}"

    def _do_request(self, entity_id):
        if self.transport is not None:
            return self.transport(self._entity_url(entity_id))
        return requests.get(
            self._entity_url(entity_id),
            headers={"Accept": SAML_METADATA_CONTENT_TYPE},
            timeout=self.timeout,
        )

    def query(self, entity_id):
        """Run one query and apply the corresponding state transition.

        Returns the resulting :class:`MdqOutcome`.
        """
        try:
            response = self._do_request(entity_id)
        except requests.RequestException as exc:
            return self._mark_unavailable(entity_id, str(exc))
        except Exception as exc:  # a broken transport must not break the state machine
            return self._mark_unavailable(entity_id, str(exc))

        status = getattr(response, "status_code", None)
        if status == 404:
            return self._handle_deleted(entity_id)
        if status != 200:
            return self._mark_unavailable(entity_id, f"HTTP {status}")

        xml_text = response.content if hasattr(response, "content") else response.text
        try:
            verify_metadata_signature(xml_text, self.trusted_fingerprints)
            parsed_entity_id, certificates = parse_entity_keys(xml_text)
        except FederationError as exc:
            logger.warning("Rejecting unverifiable MDQ record for %s: %s", entity_id, exc)
            return self._mark_unavailable(entity_id, str(exc))

        if parsed_entity_id != entity_id:
            return self._mark_unavailable(entity_id, "entityID mismatch in MDQ response")

        active = {}
        retired = {}
        previous = self._cache.get(entity_id)
        prior_retired = (
            dict(previous.retired_keys) if previous and previous.state == MdqOutcome.RECORD else {}
        )
        for certificate in certificates:
            fingerprint = certificate_fingerprint(certificate)
            if fingerprint in prior_retired:
                retired[fingerprint] = _key_from_certificate(certificate, retired=True)
            else:
                active[fingerprint] = _key_from_certificate(certificate)
        # Retirements confirmed locally stay retired even when a fresh record
        # no longer carries the key material at all.
        for fingerprint, material in prior_retired.items():
            retired.setdefault(fingerprint, material)

        self._cache[entity_id] = _CacheEntry(
            entity_id=entity_id,
            state=MdqOutcome.RECORD,
            active_keys=active,
            retired_keys=retired,
        )
        self.source_available = True
        return MdqOutcome.RECORD

    def _handle_deleted(self, entity_id):
        previous = self._cache.get(entity_id)
        retired = previous.retired_keys if previous else {}
        self._cache[entity_id] = _CacheEntry(
            entity_id=entity_id,
            state=MdqOutcome.DELETED,
            active_keys={},
            retired_keys=dict(retired),
        )
        self.source_available = True
        return MdqOutcome.DELETED

    def _mark_unavailable(self, entity_id, reason):
        logger.warning("MDQ unavailable for %s (%s); retaining last authoritative state", entity_id, reason)
        self.source_available = False
        if entity_id not in self._cache:
            self._cache[entity_id] = _CacheEntry(
                entity_id=entity_id,
                state=MdqOutcome.UNAVAILABLE,
            )
        # Existing entries keep their prior RECORD/DELETED state untouched.
        return MdqOutcome.UNAVAILABLE

    def retire(self, entity_id, fingerprint):
        """Persist an operator-confirmed retirement inside the MDQ cache."""
        entry = self._cache.get(entity_id)
        if entry is None or entry.state != MdqOutcome.RECORD:
            raise FederationError(f"Cannot retire key for unknown or unrecorded entity {entity_id}")
        material = entry.active_keys.pop(fingerprint, None)
        if material is None:
            raise FederationError(f"Key {fingerprint} is not an active key for {entity_id}")
        entry.retired_keys[fingerprint] = KeyMaterial(
            fingerprint=material.fingerprint,
            certificate_b64=material.certificate_b64,
            public_key=material.public_key,
            retired=True,
        )

    def trust_view(self, entity_id):
        entry = self._cache.get(entity_id)
        if entry is None:
            return None
        if entry.state == MdqOutcome.DELETED:
            raise EntityDeleted(entity_id)
        if entry.state == MdqOutcome.UNAVAILABLE and not entry.active_keys and not entry.retired_keys:
            raise MdqQueryError(entity_id)
        return entry.trust_view()


class FederationTrustResolver:
    """Combines static signed metadata with on-demand MDQ lookups.

    Static sources are authoritative for the entities they contain and are
    consulted first. Everything else is resolved through the MDQ client.
    Retirements recorded on either side are durable and survive outages.
    """

    def __init__(self, static_sources=None, mdq_client=None):
        self.static_sources = list(static_sources or [])
        self.mdq_client = mdq_client

    def add_static_source(self, source):
        self.static_sources.append(source)

    def trust_view(self, entity_id):
        """Return an immutable trust view for the entity.

        Static entities are served without any network access. Dynamic
        entities trigger an MDQ query; on failure the last authoritative view
        (including any retirement) is returned.
        """
        for source in self.static_sources:
            view = source.trust_view(entity_id)
            if view is not None:
                return view

        if self.mdq_client is None:
            raise FederationError(f"No trust source available for {entity_id}")

        self.mdq_client.query(entity_id)
        return self.mdq_client.trust_view(entity_id)

    def retire(self, entity_id, fingerprint):
        """Record a retirement against whichever source owns the entity."""
        for source in self.static_sources:
            if source.trust_view(entity_id) is not None:
                source.retire(entity_id, fingerprint)
                return
        if self.mdq_client is None:
            raise FederationError(f"Unknown entity {entity_id}")
        self.mdq_client.retire(entity_id, fingerprint)

    def verify(self, entity_id, fingerprint, signature, signed_bytes):
        """Verify ``signature`` over ``signed_bytes`` using an explicit view.

        The trust view is captured before the cryptographic check and is the
        sole authority for this verification, so in-flight requests use a
        stable view even if a background refresh changes the cache.
        """
        view = self.trust_view(entity_id)
        return self.verify_with_view(view, fingerprint, signature, signed_bytes)

    @staticmethod
    def verify_with_view(view, fingerprint, signature, signed_bytes):
        if view.is_retired(fingerprint):
            raise KeyRetired(fingerprint)
        material = next((key for key in view.active_keys if key.fingerprint == fingerprint), None)
        if material is None:
            raise FederationError(f"Key {fingerprint} is not in the trust view for {view.entity_id}")
        try:
            material.public_key.verify(signature, signed_bytes, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature as exc:
            raise SignatureVerificationError("Signature failed verification") from exc
        return True
