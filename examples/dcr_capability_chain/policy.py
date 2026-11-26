"""Partner approval policy store (mock, in memory).

This module is the *approval source of truth*. The OAuth layers below never
decide by themselves what a given partner may do: they look the answer up
here. Keeping the policy in one place is what lets an operator tighten the
capabilities of an already-registered client without touching the client row.
"""

# Server-wide ceilings, advertised through RFC 8414 discovery metadata.
# A client can never be granted more than the server implements.
SERVER_GRANTS = ["authorization_code", "refresh_token", "client_credentials"]
SERVER_SCOPES = ["openid", "profile", "email", "orders:read", "orders:write"]

# Two approval records for two different partners. Each record is the answer
# to "what is this partner *approved* for", independent of any one client.
PARTNER_POLICIES = {
    # Standard partner: interactive login only, read-only orders.
    "partner-standard": {
        "partner_id": "partner-standard",
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile", "email", "orders:read"],
    },
    # Premium partner: may also call the machine-to-machine grant and write.
    "partner-premium": {
        "partner_id": "partner-premium",
        "grant_types": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
        ],
        "scopes": [
            "openid",
            "profile",
            "email",
            "orders:read",
            "orders:write",
        ],
    },
}

# Initial Access Tokens (RFC 7591 calls the credential presented at the
# registration endpoint an initial access token). Each is bound to one
# partner policy, which is how the registration endpoint knows whose approval
# record to enforce.
INITIAL_ACCESS_TOKENS = {
    "iat-standard-001": "partner-standard",
    "iat-premium-001": "partner-premium",
}


class Policy:
    """Read/write facade over the in-memory approval records."""

    def __init__(self):
        # A mutable copy so the demo can widen an approval at runtime.
        self._policies = {
            pid: {
                "partner_id": rec["partner_id"],
                "grant_types": list(rec["grant_types"]),
                "scopes": list(rec["scopes"]),
            }
            for pid, rec in PARTNER_POLICIES.items()
        }
        self._tokens = dict(INITIAL_ACCESS_TOKENS)

    def partner_for_token(self, initial_access_token):
        """Resolve an initial access token to a partner id, or None."""
        if not initial_access_token:
            return None
        return self._tokens.get(initial_access_token)

    def get(self, partner_id):
        return self._policies.get(partner_id)

    def grant(self, partner_id):
        record = self.get(partner_id)
        return set(record["grant_types"]) if record else set()

    def scopes(self, partner_id):
        record = self.get(partner_id)
        return set(record["scopes"]) if record else set()

    def widen(self, partner_id, grant_types=(), scopes=()):
        """Operator action: approve additional capabilities for a partner.

        Existing clients pick the new ceiling up automatically because the
        grant layer consults this live policy, not a frozen copy stored on the
        client row.
        """
        record = self.get(partner_id)
        if record is None:
            raise KeyError(partner_id)
        for grant in grant_types:
            if grant in SERVER_GRANTS and grant not in record["grant_types"]:
                record["grant_types"].append(grant)
        for scope in scopes:
            if scope in SERVER_SCOPES and scope not in record["scopes"]:
                record["scopes"].append(scope)
        return record


class PolicyViolation(Exception):
    """Raised when requested client metadata exceeds the partner approval.

    Carries an RFC 7591 style machine-readable ``error`` code plus a human
    description naming the offending field and values, so the registration /
    configuration endpoints can turn it into a 400 ``invalid_client_metadata``
    response instead of a 500.
    """

    def __init__(self, field, requested, allowed):
        self.field = field
        self.requested = requested
        self.allowed = allowed
        super().__init__(
            f"{field} {sorted(requested)} exceeds approved {sorted(allowed)}"
        )


def enforce(partner_id, requested_grants, requested_scopes, policy):
    """Intersection + explicit-reject decision used by both DCR endpoints.

    RFC 7591 lets a server either reject or substitute a value. We make a
    deliberate distinction:

    * grant types are a hard boundary. Asking for an unapproved grant is a
      protocol-level capability request, so it is rejected loudly.
    * scopes are clamped to the approved set (substitution), which matches
      how the token endpoint filters scopes later in the chain.
    """
    approved_grants = policy.grant(partner_id)
    unapproved_grants = set(requested_grants) - approved_grants
    if unapproved_grants:
        raise PolicyViolation("grant_types", unapproved_grants, approved_grants)

    approved_scopes = policy.scopes(partner_id)
    clamped_scopes = [s for s in requested_scopes if s in approved_scopes]
    return sorted(requested_grants), sorted(clamped_scopes)
