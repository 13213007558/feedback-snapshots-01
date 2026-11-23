"""Shareable diagnostics for SAML response processing.

The diagnostics object records the trust material that was used, how far a
response got through processing and whether an identity was finally published.
Only an explicit allow-list of fields is exposed by :meth:`ResponseDiagnostics.to_dict`;
SAML attributes, response XML, NameIDs and attribute values are never stored.
"""

import hashlib
import json
import logging
import os
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.serialization import Encoding


logger = logging.getLogger(__name__)

SCHEMA = "pysaml2-response-diagnostics/1"

STAGE_REQUEST_BINDING = "request_binding"
STAGE_RESPONSE_VALIDATION = "response_validation"
STAGE_SIGNATURE_VERIFICATION = "signature_verification"
STAGE_ASSERTION_SELECTION = "assertion_selection"
STAGE_ATTRIBUTE_MAPPING = "attribute_mapping"
STAGE_IDENTITY_ISSUANCE = "identity_issuance"

OUTCOME_PASSED = "passed"
OUTCOME_FAILED = "failed"
OUTCOME_SKIPPED = "skipped"

APPROVED_REQUEST_FIELDS = frozenset(["request_id", "in_response_to", "issuer_display", "request_bound"])
APPROVED_TRUST_FIELDS = frozenset(
    ["source", "version", "issuer_display", "used", "certificate_sha256"]
)
APPROVED_STAGE_FIELDS = {
    STAGE_REQUEST_BINDING: frozenset(["request_id", "in_response_to", "issuer_display", "request_bound"]),
    STAGE_RESPONSE_VALIDATION: frozenset(
        ["request_id", "request_bound", "in_response_to_ok", "destination_ok", "status_ok"]
    ),
    STAGE_SIGNATURE_VERIFICATION: frozenset(
        [
            "request_id",
            "request_bound",
            "signed_node",
            "verified",
            "issuer_display",
            "trust_material_version",
            "certificate_sha256",
        ]
    ),
    STAGE_ASSERTION_SELECTION: frozenset(
        ["request_id", "request_bound", "assertion_count", "signed", "validated"]
    ),
    STAGE_ATTRIBUTE_MAPPING: frozenset(
        [
            "request_id",
            "request_bound",
            "asserted_attribute_count",
            "mapped_attribute_count",
            "unmapped_attribute_count",
        ]
    ),
    STAGE_IDENTITY_ISSUANCE: frozenset(["request_id", "request_bound", "published"]),
}
APPROVED_STAGE_META_FIELDS = frozenset(["stage", "outcome"])

_MAX_SAFE_STRING = 512


def _safe_string(value):
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > _MAX_SAFE_STRING:
        return None
    if any(ord(char) < 0x20 for char in value):
        return None
    if "<" in value or ">" in value:
        # Never let markup (for example a captured SAML body) travel in an
        # approved scalar field.
        return None
    return value


def _safe_bool(value):
    return value if isinstance(value, bool) else None


def _safe_int(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0 or value > 1_000_000:
        return None
    return value


def _sanitize_value(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return _safe_int(value)
    if isinstance(value, str):
        return _safe_string(value)
    return None


def _safe_source(source):
    """Return a shareable label for a metadata source.

    Local paths are reduced to their basename and URL query/fragment parts are
    dropped so that a diagnostic can be shared without revealing a host's
    directory layout or credentials carried in a URL.
    """
    if not source:
        return None
    source = str(source)
    try:
        parsed = urlsplit(source)
    except ValueError:
        return None
    if parsed.scheme in ("http", "https"):
        return _safe_string(f"{parsed.scheme}://{parsed.netloc}{parsed.path}")
    return _safe_string(os.path.basename(source))


def _material_version(store):
    content = None
    getter = getattr(store, "get_metadata_content", None)
    if callable(getter):
        try:
            content = getter()
        except Exception:
            content = None
    if content is None:
        raw = getattr(store, "metadata", None)
        if isinstance(raw, bytes):
            content = raw
        elif isinstance(raw, str) and raw:
            content = raw
    if content is None:
        descriptor = getattr(store, "entities_descr", None) or getattr(store, "entity_descr", None)
        if descriptor is not None:
            content = str(descriptor)
    if content is None:
        return None
    if isinstance(content, str):
        content = content.encode("utf-8")
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _pem_bytes(data):
    from saml2.sigver import pem_format

    if isinstance(data, str):
        data = data.encode("ascii")
    if b"-----BEGIN CERTIFICATE-----" in data:
        return data
    return pem_format(data.decode("ascii"))


def certificate_fingerprint(data):
    """Return the SHA-256 fingerprint of a PEM/DER certificate, or None."""
    if not data:
        return None
    try:
        from saml2.cryptography import pki

        cert = pki.load_x509_certificate(_pem_bytes(data), "pem")
        return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
    except Exception:
        return None


def _metadata_certificate_fingerprint(cert_body):
    if not cert_body:
        return None
    try:
        return certificate_fingerprint(_pem_bytes(str(cert_body).encode("ascii")))
    except Exception:
        return None


def describe_trust_materials(metadata, issuer, used_certificate=None, used_certificate_sha256=None):
    """Describe the local trust material that can confirm ``issuer``.

    Only source labels, material digests, certificate fingerprints and a
    boolean saying whether the material supplied the certificate that actually
    verified the signature are returned.
    """
    if used_certificate_sha256:
        used_fingerprint = used_certificate_sha256
    else:
        used_fingerprint = certificate_fingerprint(used_certificate)
    records = []
    stores = getattr(metadata, "metadata", None)
    if isinstance(stores, dict):
        items = stores.items()
    else:
        items = [("", metadata)]

    for key, store in items:
        try:
            cert_entries = store.certs(issuer, "any", "signing")
        except Exception:
            continue
        source = _safe_source(getattr(store, "filename", None) or getattr(store, "url", None) or key)
        version = _material_version(store)
        for _key_name, cert_body in cert_entries:
            fingerprint = _metadata_certificate_fingerprint(cert_body)
            if not fingerprint:
                continue
            records.append(
                {
                    "source": source,
                    "version": version,
                    "issuer_display": _safe_string(issuer),
                    "used": bool(used_fingerprint and fingerprint == used_fingerprint),
                    "certificate_sha256": fingerprint,
                }
            )

    if used_fingerprint and not any(record["used"] for record in records):
        records.append(
            {
                "source": "message",
                "version": None,
                "issuer_display": _safe_string(issuer),
                "used": True,
                "certificate_sha256": used_fingerprint,
            }
        )

    deduplicated = {}
    for record in records:
        deduplicated[(record["source"], record["version"], record["certificate_sha256"], record["used"])] = record
    return sorted(
        deduplicated.values(),
        key=lambda item: (str(item.get("source")), str(item.get("version")), str(item.get("certificate_sha256"))),
    )


class ResponseDiagnostics:
    """Structured, shareable audit trail for one response/request pair.

    The object intentionally offers no way to record raw SAML attributes,
    attribute values, response bodies or account identifiers.  ``to_dict`` and
    ``to_json`` only emit the approved fields listed in this module.
    """

    def __init__(self, request_id=None):
        self._request = {
            "request_id": _safe_string(request_id),
            "response_id": None,
            "in_response_to": None,
            "issuer_display": None,
            "request_bound": None,
        }
        self._stages = []
        self._trust_materials = []
        self._identity_published = False
        self._request_binding_recorded = False

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------
    def bind_request(self, request_id=None, in_response_to=None):
        if request_id is not None:
            self._request["request_id"] = _safe_string(request_id)
        if in_response_to is not None:
            self._request["in_response_to"] = _safe_string(in_response_to)

    def bind_response(self, response):
        """Bind the diagnostic to a parsed SAML response without retaining it."""
        if response is None:
            return
        self._request["response_id"] = _safe_string(getattr(response, "id", None))
        self._request["in_response_to"] = _safe_string(getattr(response, "in_response_to", None))
        issuer = getattr(response, "issuer", None)
        self._request["issuer_display"] = _safe_string(getattr(issuer, "text", None))

    def mark_request_bound(self, request_bound):
        self._request["request_bound"] = bool(request_bound)

    @property
    def request_bound(self):
        return self._request.get("request_bound")

    @property
    def request_binding_recorded(self):
        return self._request_binding_recorded

    @property
    def request_id(self):
        return self._request.get("request_id")

    @property
    def issuer_display(self):
        return self._request.get("issuer_display")

    def used_trust_material(self, issuer_display=None, certificate_sha256=None):
        for material in self._trust_materials:
            if not material.get("used"):
                continue
            if issuer_display and material.get("issuer_display") != issuer_display:
                continue
            if certificate_sha256 and material.get("certificate_sha256") != certificate_sha256:
                continue
            return material
        return None

    def record_trust_material(self, metadata, issuer, used_certificate=None, used_certificate_sha256=None):
        try:
            described = describe_trust_materials(
                metadata,
                issuer,
                used_certificate=used_certificate,
                used_certificate_sha256=used_certificate_sha256,
            )
        except Exception:  # diagnostics must never break response processing
            logger.debug("Could not describe trust material", exc_info=True)
            return
        existing = {
            (item.get("source"), item.get("version"), item.get("certificate_sha256"), item.get("used"))
            for item in self._trust_materials
        }
        for item in described:
            key = (item.get("source"), item.get("version"), item.get("certificate_sha256"), item.get("used"))
            if key not in existing:
                self._trust_materials.append(item)
                existing.add(key)

    def record_stage(self, stage, outcome, **details):
        if stage not in APPROVED_STAGE_FIELDS:
            raise ValueError(f"Unknown diagnostic stage: {stage}")
        if outcome not in (OUTCOME_PASSED, OUTCOME_FAILED, OUTCOME_SKIPPED):
            raise ValueError(f"Unknown diagnostic outcome: {outcome}")

        allowed = APPROVED_STAGE_FIELDS[stage]
        safe_details = {}
        for key, value in details.items():
            if key not in allowed:
                continue
            if isinstance(value, bool):
                safe_details[key] = value
            elif isinstance(value, int):
                safe = _safe_int(value)
                if safe is not None:
                    safe_details[key] = safe
            elif isinstance(value, str):
                safe = _safe_string(value)
                if safe is not None:
                    safe_details[key] = safe

        stage_entry = {"stage": stage, "outcome": outcome}
        stage_entry.update(safe_details)
        self._stages.append(stage_entry)
        return stage_entry

    def record_signature(
        self,
        verified,
        signed_node=None,
        issuer_display=None,
        trust_material_version=None,
        certificate_sha256=None,
        request_bound=None,
        outcome=None,
    ):
        return self.record_stage(
            STAGE_SIGNATURE_VERIFICATION,
            outcome or (OUTCOME_PASSED if verified else OUTCOME_FAILED),
            request_id=self.request_id,
            request_bound=request_bound,
            signed_node=signed_node,
            verified=bool(verified),
            issuer_display=issuer_display,
            trust_material_version=trust_material_version,
            certificate_sha256=certificate_sha256,
        )

    def record_assertion_selection(
        self, passed, assertion_count=None, signed=None, validated=None, request_bound=None
    ):
        return self.record_stage(
            STAGE_ASSERTION_SELECTION,
            OUTCOME_PASSED if passed else OUTCOME_FAILED,
            request_id=self.request_id,
            request_bound=request_bound,
            assertion_count=assertion_count,
            signed=signed if isinstance(signed, bool) else None,
            validated=validated if isinstance(validated, bool) else None,
        )

    def record_attribute_mapping(
        self,
        passed,
        asserted_attribute_count,
        mapped_attribute_count,
        unmapped_attribute_count=None,
        request_bound=None,
    ):
        return self.record_stage(
            STAGE_ATTRIBUTE_MAPPING,
            OUTCOME_PASSED if passed else OUTCOME_FAILED,
            request_id=self.request_id,
            request_bound=request_bound,
            asserted_attribute_count=asserted_attribute_count,
            mapped_attribute_count=mapped_attribute_count,
            unmapped_attribute_count=unmapped_attribute_count,
        )

    def record_identity_issuance(self, published, request_bound=None):
        self._identity_published = bool(published)
        return self.record_stage(
            STAGE_IDENTITY_ISSUANCE,
            OUTCOME_PASSED if published else OUTCOME_FAILED,
            request_id=self.request_id,
            request_bound=request_bound,
            published=bool(published),
        )

    def record_response_validation(
        self, passed, in_response_to_ok=None, destination_ok=None, status_ok=None, request_bound=None
    ):
        return self.record_stage(
            STAGE_RESPONSE_VALIDATION,
            OUTCOME_PASSED if passed else OUTCOME_FAILED,
            request_id=self.request_id,
            request_bound=request_bound,
            in_response_to_ok=in_response_to_ok,
            destination_ok=destination_ok,
            status_ok=status_ok,
        )

    def record_request_binding(self, request_bound):
        return self.record_stage(
            STAGE_REQUEST_BINDING,
            OUTCOME_PASSED if request_bound else OUTCOME_FAILED,
            request_id=self.request_id,
            in_response_to=self._request.get("in_response_to"),
            issuer_display=self._request.get("issuer_display"),
            request_bound=bool(request_bound),
        )

    # ------------------------------------------------------------------
    # Public views
    # ------------------------------------------------------------------
    @property
    def failure_stage(self):
        for stage in self._stages:
            if stage["outcome"] == OUTCOME_FAILED:
                return stage["stage"]
        return None

    @property
    def identity_published(self):
        return self._identity_published

    @property
    def outcome(self):
        return OUTCOME_FAILED if self.failure_stage else "succeeded"

    def to_dict(self):
        """Return the approved, shareable representation of this diagnostic.

        Values are sanitized again on the way out, so the serializer stays an
        allow-list even if internal bookkeeping was tampered with.
        """
        request = {
            key: _sanitize_value(value) for key, value in self._request.items() if key in APPROVED_REQUEST_FIELDS
        }
        trust_materials = [
            {key: _sanitize_value(item.get(key)) for key in APPROVED_TRUST_FIELDS} for item in self._trust_materials
        ]

        stages = []
        for item in self._stages:
            stage = item["stage"]
            if stage not in APPROVED_STAGE_FIELDS:
                continue
            allowed = APPROVED_STAGE_META_FIELDS | APPROVED_STAGE_FIELDS[stage]
            stages.append({key: _sanitize_value(value) for key, value in item.items() if key in allowed})

        return {
            "schema": SCHEMA,
            "request": request,
            "trust_materials": trust_materials,
            "stages": stages,
            "failure_stage": self.failure_stage,
            "outcome": self.outcome,
            "identity_published": self.identity_published,
        }

    def to_json(self):
        """Serialize this diagnostic into a shareable ticket payload."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    def to_ticket(self):
        """Alias for :meth:`to_json`, the serialized support-ticket payload."""
        return self.to_json()

    def __repr__(self):
        return f"{self.__class__.__name__}({self.to_json()})"

    def __str__(self):
        return self.to_json()
