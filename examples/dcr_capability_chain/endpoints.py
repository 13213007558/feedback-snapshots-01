"""RFC 7591 / 7592 endpoints wired to the partner approval policy.

These classes stay on Authlib's standard extension points. The generic
metadata *shape* (types, URLs, jwks, server ceiling) is validated by
ClientMetadataClaims. The per-partner *entitlement* decision (may this partner
use this grant or scope?) lives in PartnerEntitlementClaims, which the
endpoint primes with the current partner before validation. By the time
save_client/update_client run, the metadata is already policy-conformant.
"""

import secrets

from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint
from authlib.oauth2.rfc7592 import ClientConfigurationEndpoint

from .claims import PartnerEntitlementClaims
from .models import Client
from .models import RegistrationToken


def _bearer(request):
    header = request.headers.get("Authorization", "")
    parts = header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


class _EntitlementContext:
    """Shared extract logic that primes the claims class per request."""

    claims_classes = [PartnerEntitlementClaims]

    def _prime_entitlement(self, partner_id):
        PartnerEntitlementClaims.active_partner_id = partner_id
        PartnerEntitlementClaims.active_policy = self.db.policy

    def extract_client_metadata(self, request):
        self._prime_entitlement(request.partner_id)
        return super().extract_client_metadata(request)


class RegistrationEndpoint(_EntitlementContext, ClientRegistrationEndpoint):
    """RFC 7591 dynamic registration with partner-entitlement enforcement."""

    def __init__(self, server, db, server_metadata):
        super().__init__(server, claims_classes=[PartnerEntitlementClaims])
        self.db = db
        self._server_metadata = server_metadata

    def get_server_metadata(self):
        return self._server_metadata

    # Layer 1 gate: the initial access token identifies the partner.
    def authenticate_token(self, request):
        token = _bearer(request)
        partner_id = self.db.policy.partner_for_token(token)
        if not partner_id:
            return None
        request.partner_id = partner_id
        return token

    def generate_client_id(self, request):
        return "cid-" + secrets.token_urlsafe(12)

    def generate_client_secret(self, request, client_metadata=None):
        return "sec-" + secrets.token_urlsafe(24)

    def generate_client_registration_info(self, client, request):
        """Issue the RFC 7592 registration access token + management URI."""
        rat = "rat-" + secrets.token_urlsafe(24)
        self.db.session.add(
            RegistrationToken(
                access_token=rat, client_id=client.get_client_id(), revoked=0
            )
        )
        self.db.session.commit()
        return {
            "registration_client_uri": (
                f"{self._server_metadata['issuer']}/register/"
                f"{client.get_client_id()}"
            ),
            "registration_access_token": rat,
        }

    def save_client(self, client_info, client_metadata, request):
        # Metadata is already validated and policy-clamped at this point.
        client = Client(
            client_id=client_info["client_id"],
            client_secret=client_info.get("client_secret"),
            partner_id=request.partner_id,
            metadata=client_metadata,
        )
        self.db.session.add(client)
        self.db.session.commit()
        return client


class ConfigurationEndpoint(_EntitlementContext, ClientConfigurationEndpoint):
    """RFC 7592 read/update/delete, re-applying the same entitlement gate."""

    def __init__(self, server, db, server_metadata):
        super().__init__(server, claims_classes=[PartnerEntitlementClaims])
        self.db = db
        self._server_metadata = server_metadata

    def get_server_metadata(self):
        return self._server_metadata

    def extract_client_metadata(self, request):
        # On PUT the partner is read from the existing client, not a token map.
        self._prime_entitlement(request.client.partner_id)
        return ClientRegistrationEndpoint.extract_client_metadata(self, request)

    def authenticate_token(self, request):
        rat = _bearer(request)
        if not rat:
            return None
        return (
            self.db.session.query(RegistrationToken)
            .filter_by(access_token=rat, revoked=0)
            .first()
        )

    def authenticate_client(self, request):
        client_id = request.uri.rstrip("/").rsplit("/", 1)[-1]
        return self.db.session.query(Client).filter_by(client_id=client_id).first()

    def revoke_access_token(self, token, request):
        token.revoked = 1
        self.db.session.commit()

    def check_permission(self, client, request):
        # The token was already proven to belong to this client upstream.
        return True

    def delete_client(self, client, request):
        self.db.session.delete(client)
        self.db.session.commit()

    def update_client(self, client, client_metadata, request):
        client.set_client_metadata(client_metadata)
        self.db.session.add(client)
        self.db.session.commit()
        return client

    def generate_client_registration_info(self, client, request):
        return {
            "registration_client_uri": request.uri,
            "registration_access_token": _bearer(request),
        }
