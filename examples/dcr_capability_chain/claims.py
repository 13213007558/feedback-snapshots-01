"""Client metadata claims that apply the partner approval policy.

ClientMetadataClaims already validates shape/types and the server ceiling
(via get_claims_options). This subclass adds the *per-partner entitlement*
decision during validation, so the values returned by get_registered_claims
are already the final, policy-conformant ones that get persisted and echoed.

The endpoint sets ``active_partner_id`` on the shared claims instance before
each request so validation knows whose approval record to apply.
"""

from authlib.oauth2.rfc7591 import ClientMetadataClaims
from authlib.oauth2.rfc7591 import InvalidClientMetadataError

from .policy import PolicyViolation
from .policy import enforce


class PartnerEntitlementClaims(ClientMetadataClaims):
    #: Set per request by the registration/configuration endpoint.
    active_partner_id = None
    active_policy = None

    def validate_grant_types(self):
        # RFC 7591 default when the client omits grant_types.
        grants = self.get("grant_types") or ["authorization_code"]
        self["grant_types"] = grants
        scopes = self.get("scope", "").split()
        try:
            final_grants, final_scopes = enforce(
                self.active_partner_id,
                grants,
                scopes,
                self.active_policy,
            )
        except PolicyViolation as exc:
            # RFC 7591 3.2.2 -> 400 invalid_client_metadata naming the field.
            raise InvalidClientMetadataError(str(exc)) from exc
        self["grant_types"] = final_grants
        self["scope"] = " ".join(final_scopes)

    def validate_scope(self):
        # Scope clamping already happened in validate_grant_types; keep the
        # base method (no-op by default) for forward compatibility.
        super().validate_scope()
