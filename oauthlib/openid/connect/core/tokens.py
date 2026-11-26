"""
authlib.openid.connect.core.tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module contains methods for adding JWT tokens to requests.
"""
from oauthlib.oauth2.rfc6749.consent import enforce_access_token_consent
from oauthlib.oauth2.rfc6749.tokens import (
    TokenBase, _required_scope_copy, get_token_from_header,
    random_token_generator,
)


class JWTToken(TokenBase):
    __slots__ = (
        'request_validator', 'token_generator',
        'refresh_token_generator', 'expires_in'
    )

    def __init__(self, request_validator=None, token_generator=None,
                 expires_in=None, refresh_token_generator=None):
        self.request_validator = request_validator
        self.token_generator = token_generator or random_token_generator
        self.refresh_token_generator = (
            refresh_token_generator or self.token_generator
        )
        self.expires_in = expires_in or 3600

    def create_token(self, request, refresh_token=False):
        """Create a JWT Token, using requestvalidator method."""

        expires_in = self.expires_in(request) if callable(self.expires_in) else self.expires_in

        request.expires_in = expires_in

        return self.request_validator.get_jwt_bearer_token(None, None, request)

    def validate_request(self, request):
        token = get_token_from_header(request)
        required_scopes = _required_scope_copy(request.scopes)
        # Hand the validator its own copy: the requirement captured for the
        # live-consent check must not change through an in-place mutation.
        if not self.request_validator.validate_jwt_bearer_token(
                token, _required_scope_copy(required_scopes), request):
            return False
        return enforce_access_token_consent(
            self.request_validator, token, request, required_scopes)

    def estimate_type(self, request):
        token = get_token_from_header(request)
        if token and token.startswith('ey') and token.count('.') in (2, 4):
            return 10
        return 0
