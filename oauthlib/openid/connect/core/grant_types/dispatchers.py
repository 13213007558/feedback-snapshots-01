import logging

from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.utils import (
    SCOPE_PROVENANCE_NOT_IMPLEMENTED, SCOPE_PROVENANCE_UNKNOWN,
    authorization_code_scope_provenance, openid_in_code_provenance,
)

log = logging.getLogger(__name__)


class Dispatcher:
    default_grant = None
    oidc_grant = None


class AuthorizationCodeGrantDispatcher(Dispatcher):
    """
    This is an adapter class that will route simple Authorization Code
    requests, those that have `response_type=code` and a scope including
    `openid` to either the `default_grant` or the `oidc_grant` based on
    the scopes requested.
    """
    def __init__(self, default_grant=None, oidc_grant=None):
        self.default_grant = default_grant
        self.oidc_grant = oidc_grant

    def _handler_for_request(self, request):
        handler = self.default_grant

        if request.scopes and "openid" in request.scopes:
            handler = self.oidc_grant

        log.debug('Selecting handler for request %r.', handler)
        return handler

    def create_authorization_response(self, request, token_handler):
        """Read scope and route to the designated handler."""
        return self._handler_for_request(request).create_authorization_response(request, token_handler)

    def validate_authorization_request(self, request):
        """Read scope and route to the designated handler."""
        return self._handler_for_request(request).validate_authorization_request(request)


class ImplicitTokenGrantDispatcher(Dispatcher):
    """
    This is an adapter class that will route simple Authorization
    requests, those that have `id_token` in `response_type` and a scope
    including `openid` to either the `default_grant` or the `oidc_grant`
    based on the scopes requested.
    """
    def __init__(self, default_grant=None, oidc_grant=None):
        self.default_grant = default_grant
        self.oidc_grant = oidc_grant

    def _handler_for_request(self, request):
        handler = self.default_grant

        if request.scopes and "openid" in request.scopes and 'id_token' in request.response_type:
            handler = self.oidc_grant

        log.debug('Selecting handler for request %r.', handler)
        return handler

    def create_authorization_response(self, request, token_handler):
        """Read scope and route to the designated handler."""
        return self._handler_for_request(request).create_authorization_response(request, token_handler)

    def validate_authorization_request(self, request):
        """Read scope and route to the designated handler."""
        return self._handler_for_request(request).validate_authorization_request(request)


class AuthorizationTokenGrantDispatcher(Dispatcher):
    """
    This is an adapter class that will route simple Token requests, those that authorization_code have a scope
    including 'openid' to either the default_grant or the oidc_grant based on the scopes requested.
    """
    def __init__(self, request_validator, default_grant=None, oidc_grant=None):
        self.default_grant = default_grant
        self.oidc_grant = oidc_grant
        self.request_validator = request_validator

    def _handler_for_request(self, request):
        handler = self.default_grant
        parameters = dict(request.decoded_body)
        client_id = parameters.get('client_id')
        code = parameters.get('code')
        redirect_uri = parameters.get('redirect_uri')

        # If code is not present fallback to `default_grant` which will
        # raise an error for the missing `code` in `create_token_response` step.
        if code:
            # Route on the scopes/protocol approved when the code was issued,
            # never on the current token-request scopes or client defaults.
            provenance = authorization_code_scope_provenance(
                self.request_validator, client_id, code, redirect_uri, request
            )
            # Stash the routing provenance on the request for observability;
            # the grant re-resolves it after validate_code and pins scopes.
            request.authorization_code_scope_provenance = provenance
            if provenance is SCOPE_PROVENANCE_UNKNOWN:
                log.warning(
                    'Authorization code %r for client %r has no provable '
                    'approved-scope origin; routing as plain OAuth 2.0.',
                    code, client_id,
                )
            if provenance is SCOPE_PROVENANCE_NOT_IMPLEMENTED:
                # No stored-scope lookup exists, so the protocol cannot be
                # chosen before code validation. The OIDC grant is a superset
                # of the OAuth code grant and its id_token modifier makes the
                # final decision from the scopes that ``validate_code``
                # restores from the persisted grant.
                handler = self.oidc_grant
            elif openid_in_code_provenance(provenance, request.scopes):
                handler = self.oidc_grant

        log.debug('Selecting handler for request %r.', handler)
        return handler

    def create_token_response(self, request, token_handler):
        """Read scope and route to the designated handler."""
        try:
            handler = self._handler_for_request(request)
        except errors.OAuth2Error as error:
            # A validator may enforce a strict disposition for legacy codes by
            # raising (e.g. InvalidGrantError) from its scope lookup while
            # routing. Render it like any other token endpoint error.
            headers = {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-store',
                'Pragma': 'no-cache',
            }
            headers.update(error.headers or {})
            return headers, error.json, error.status_code
        return handler.create_token_response(request, token_handler)
