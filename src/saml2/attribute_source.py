"""Attribute provenance and source policy for SAML service providers.

The SAML attribute mapping performed by :mod:`saml2.attribute_converter`
collapses attributes to local names.  That is fine for display attributes but
is not enough when an attribute is used to grant permissions: an encrypted
attribute and a legacy plaintext attribute can map to the same local name.

This module keeps the provenance of every mapped attribute (which assertion,
whether the assertion or attribute was encrypted, whether the assertion was
signed and verified) and applies a configurable source policy.  The mapper
view (:class:`AttributeMapping`) exposes all claims; the authorization view
(:class:`AuthorizationIdentity`) only returns values that came from a source
which satisfies the policy, and refuses to return anything for a field whose
claims conflict.

Values are never included in the descriptions used by errors or logs.
"""

from dataclasses import dataclass
import json
from typing import Any
from typing import Iterable
from typing import Mapping
from typing import Optional

from saml2 import SAMLError
from saml2.attribute_converter import list_to_local
from saml2.saml import NAME_FORMAT_UNSPECIFIED


class AttributeSourceError(SAMLError):
    """Base class for attribute source policy failures."""

    reason = "attribute_source_error"

    def __init__(self, local_name: str, fields: Iterable[Mapping[str, Any]]):
        self.local_name = local_name
        self.fields = [dict(field) for field in fields]
        detail = json.dumps(self.fields, sort_keys=True, default=str)
        super().__init__(f"Attribute source {self.reason} for '{local_name}': {detail}")


class AttributeSourceRejected(AttributeSourceError):
    """No source satisfies the configured requirements for a business field."""

    reason = "rejected"


class AttributeSourceConflict(AttributeSourceError):
    """Two sources produced different claims for the same business field."""

    reason = "conflict"


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return tuple(sorted((str(key), _freeze(val)) for key, val in value.items()))
    if isinstance(value, (list, tuple, set)):
        return tuple(_freeze(item) for item in value)
    return value


def _value_signature(values: Iterable[Any]) -> frozenset:
    return frozenset(_freeze(value) for value in values)


@dataclass(frozen=True)
class AttributeClaim:
    """A single attribute claim before it is collapsed into a local name."""

    local_name: str
    values: tuple
    attribute_name: str
    name_format: Optional[str]
    friendly_name: Optional[str]
    issuer: str
    assertion_id: str
    encrypted: bool
    signed: bool
    response_signed: bool = False
    attribute_encrypted: bool = False
    assertion_encrypted: bool = False
    qualified: bool = False

    @property
    def value_signature(self) -> frozenset:
        return _value_signature(self.values)

    @property
    def signature_verified(self) -> bool:
        return bool(self.signed or self.response_signed)

    def describe(self, qualified: Optional[bool] = None) -> dict:
        """Return identifiers that locate the field without exposing values."""
        return {
            "local_name": self.local_name,
            "attribute_name": self.attribute_name,
            "name_format": self.name_format,
            "friendly_name": self.friendly_name,
            "issuer": self.issuer,
            "assertion_id": self.assertion_id,
            "encrypted": self.encrypted,
            "assertion_encrypted": self.assertion_encrypted,
            "attribute_encrypted": self.attribute_encrypted,
            "signed": self.signed,
            "response_signed": self.response_signed,
            "qualified": self.qualified if qualified is None else qualified,
            "value_count": len(self.values),
        }


class AttributeSourcePolicy:
    """Configuration describing which sources may decide business identity.

    Example configuration::

        "attribute_source_policy": {
            "business_attributes": {
                "o": {
                    "require_encrypted": True,
                    "require_signed": True,
                    "trusted_issuers": ["https://hr.example.org/idp"],
                },
                "employeeType": {
                    "require_encrypted": True,
                    "require_signed": True,
                },
            },
            "display_attributes": ["displayName", "mail"],
        }

    ``business_attributes`` may also be a list of local names, in which case
    each field defaults to requiring a signed assertion and encryption.
    ``display_attributes`` documents fields that stay on the legacy mapper
    path; they are never consulted for authorization.
    """

    DEFAULT_REQUIREMENT = {
        "require_encrypted": True,
        "require_signed": True,
        "require_attribute_encrypted": False,
        "require_values": True,
        "required": True,
        "trusted_issuers": (),
    }

    def __init__(
        self,
        business_attributes=None,
        display_attributes=None,
        fail_on_missing=True,
        fail_on_conflict=True,
    ):
        self.business_attributes = self._normalize_business_attributes(business_attributes)
        self.display_attributes = set(display_attributes or ())
        self.fail_on_missing = bool(fail_on_missing)
        self.fail_on_conflict = bool(fail_on_conflict)

    @classmethod
    def from_config(cls, value):
        if value is None or isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise ValueError("attribute_source_policy must be a mapping")
        business_attributes = value.get("business_attributes")
        if business_attributes is None:
            business_attributes = value.get("attributes")
        return cls(
            business_attributes=business_attributes,
            display_attributes=value.get("display_attributes"),
            fail_on_missing=value.get("fail_on_missing", True),
            fail_on_conflict=value.get("fail_on_conflict", True),
        )

    @classmethod
    def _normalize_business_attributes(cls, business_attributes):
        if not business_attributes:
            return {}
        if isinstance(business_attributes, str):
            business_attributes = [business_attributes]
        if isinstance(business_attributes, (list, tuple, set)):
            return {name: dict(cls.DEFAULT_REQUIREMENT) for name in business_attributes}
        if not isinstance(business_attributes, Mapping):
            raise ValueError("business_attributes must be a mapping or a list of names")
        normalized = {}
        for name, requirement in business_attributes.items():
            if requirement is None or requirement is True:
                requirement = {}
            elif requirement is False:
                requirement = {"required": False}
            if not isinstance(requirement, Mapping):
                raise ValueError(f"Invalid source requirement for {name!r}")
            merged = dict(cls.DEFAULT_REQUIREMENT)
            merged.update(requirement)
            issuers = merged.get("trusted_issuers")
            if isinstance(issuers, str):
                issuers = [issuers]
            merged["trusted_issuers"] = tuple(issuers or ())
            normalized[name] = merged
        return normalized

    def qualifies(self, claim: AttributeClaim, requirement: Mapping[str, Any]) -> bool:
        if requirement.get("require_encrypted", True) and not claim.encrypted:
            return False
        if requirement.get("require_attribute_encrypted", False) and not claim.attribute_encrypted:
            return False
        if requirement.get("require_signed", True) and not claim.signature_verified:
            return False
        trusted_issuers = requirement.get("trusted_issuers") or ()
        if trusted_issuers and claim.issuer not in trusted_issuers:
            return False
        return True


class AttributeMapping:
    """The mapper view: every claim with its provenance plus the legacy AVA."""

    def __init__(self, claims: Iterable[AttributeClaim], ava: Optional[dict] = None):
        self.claims = list(claims)
        self.ava = dict(ava or {})

    def claims_for(self, local_name: str) -> list[AttributeClaim]:
        return [claim for claim in self.claims if claim.local_name == local_name]

    def provenance(self) -> dict:
        result = {}
        for claim in self.claims:
            result.setdefault(claim.local_name, []).append(claim.describe())
        return result

    def authorization_identity(self, policy: AttributeSourcePolicy) -> "AuthorizationIdentity":
        policy = AttributeSourcePolicy.from_config(policy)
        attributes = {}
        qualified_claims = []

        for local_name, requirement in policy.business_attributes.items():
            if local_name in policy.display_attributes:
                raise ValueError(
                    f"Attribute {local_name!r} cannot be both a business and a display attribute"
                )
            all_claims = self.claims_for(local_name)
            if not all_claims:
                if requirement.get("required", True) and policy.fail_on_missing:
                    raise AttributeSourceRejected(local_name, [])
                continue

            qualifying = [claim for claim in all_claims if policy.qualifies(claim, requirement)]
            if not qualifying:
                raise AttributeSourceRejected(
                    local_name,
                    [claim.describe(qualified=False) for claim in all_claims],
                )

            if requirement.get("require_values", True) and not any(claim.values for claim in qualifying):
                raise AttributeSourceRejected(
                    local_name,
                    [claim.describe(qualified=True) for claim in qualifying],
                )

            qualifying_signatures = {claim.value_signature for claim in qualifying}
            conflicts = len(qualifying_signatures) > 1
            if not conflicts:
                trusted_signature = next(iter(qualifying_signatures))
                conflicts = any(claim.value_signature != trusted_signature for claim in all_claims)
            if conflicts and policy.fail_on_conflict:
                raise AttributeSourceConflict(
                    local_name,
                    [claim.describe() for claim in all_claims],
                )

            attributes[local_name] = list(qualifying[0].values)
            qualified_claims.extend(qualifying)

        return AuthorizationIdentity(attributes, qualified_claims, policy)


class AuthorizationIdentity(dict):
    """The authorization consumer view: only policy-qualified business values."""

    def __init__(self, attributes, claims, policy):
        super().__init__(attributes)
        self.claims = list(claims)
        self.policy = policy

    def provenance(self) -> dict:
        result = {}
        for claim in self.claims:
            result.setdefault(claim.local_name, []).append(claim.describe())
        return result


class AttributeMapper:
    """Map one AttributeStatement into claims while retaining provenance."""

    def __init__(self, attribute_converters, allow_unknown_attributes=False):
        self.attribute_converters = attribute_converters
        self.allow_unknown_attributes = allow_unknown_attributes

    def map_statement(
        self,
        statement,
        *,
        issuer: str,
        assertion_id: str,
        assertion_encrypted: bool = False,
        assertion_signed: bool = False,
        response_signed: bool = False,
        decrypted_attribute_ids: Iterable[int] = (),
    ) -> list[AttributeClaim]:
        decrypted_ids = set(decrypted_attribute_ids)
        claims = []
        for attribute in statement.attribute:
            local = list_to_local(self.attribute_converters, [attribute], self.allow_unknown_attributes)
            if not local:
                continue
            attribute_encrypted = id(attribute) in decrypted_ids
            for local_name, values in local.items():
                claims.append(
                    AttributeClaim(
                        local_name=local_name,
                        values=tuple(values),
                        attribute_name=getattr(attribute, "name", None) or "",
                        name_format=getattr(attribute, "name_format", None) or NAME_FORMAT_UNSPECIFIED,
                        friendly_name=getattr(attribute, "friendly_name", None),
                        issuer=issuer or "",
                        assertion_id=assertion_id or "",
                        encrypted=bool(assertion_encrypted or attribute_encrypted),
                        signed=bool(assertion_signed),
                        response_signed=bool(response_signed),
                        attribute_encrypted=attribute_encrypted,
                        assertion_encrypted=bool(assertion_encrypted),
                    )
                )
        return claims
