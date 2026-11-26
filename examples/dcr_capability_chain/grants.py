"""Token-endpoint grant: the last enforcement layer in the chain.

By the time a request reaches a grant, the client has already authenticated and
its grant_type has been checked against Client.check_grant_type (which itself
intersects the live partner policy). This grant adds the runtime scope
decision: an unknown scope is an RFC 6749 invalid_scope error, while an
approved-but-not-entitled scope is silently filtered from the issued token.
"""

import secrets

from authlib.oauth2.rfc6749 import InvalidScopeError
from authlib.oauth2.rfc6749 import JsonResponse
from authlib.oauth2.rfc6749 import UnauthorizedClientError
from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant

from .models import AccessToken


class ScopedClientCredentialsGrant(ClientCredentialsGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic"]

    def validate_token_request(self):
        client = self.authenticate_token_endpoint_client()
        # UnauthorizedClientError if the (possibly tightened) policy no longer
        # allows client_credentials for this client.
        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(
                f"The client is not authorized to use 'grant_type={self.GRANT_TYPE}'"
            )
        self.request.client = client

        requested = self.request.payload.scope or ""
        requested_scopes = requested.split()
        # Unknown scope values are a hard protocol error, not silent filtering.
        supported = set(self.server.scopes_supported or [])
        if requested_scopes and not supported.issuperset(requested_scopes):
            raise InvalidScopeError()
        # Approved-but-not-entitled scopes are filtered via the live policy.
        # The Flask form payload is immutable, so keep the clamped scope on the
        # grant and read it back when minting the token.
        self.granted_scope = client.get_allowed_scope(requested)

    def create_token_response(self):
        token = self.generate_token(
            scope=self.granted_scope, include_refresh_token=False
        )
        self.save_token(token)
        return JsonResponse(token, headers=self.TOKEN_RESPONSE_HEADER)

    def save_token(self, token):
        access = AccessToken(
            access_token=token["access_token"],
            client_id=self.request.client.get_client_id(),
            scope=token.get("scope", ""),
            revoked=0,
        )
        self.server.demo_db.session.add(access)
        self.server.demo_db.session.commit()

    def generate_token(self, *args, **kwargs):
        token = super().generate_token(*args, **kwargs)
        token["access_token"] = "tok-" + secrets.token_urlsafe(24)
        return token
