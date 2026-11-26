"""
oauthlib.oauth2.rfc6749.grant_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import json
import logging

from .. import errors, utils
from ..consent import (
    CONSENT_UNKNOWN, intersect_scopes, publish_current_consent,
    resolve_current_consent_scopes,
)
from .base import GrantTypeBase
from oauthlib.common import log_safe

log = logging.getLogger(__name__)


class RefreshTokenGrant(GrantTypeBase):

    """`Refresh token grant`_

    .. _`Refresh token grant`: https://tools.ietf.org/html/rfc6749#section-6
    """

    def __init__(self, request_validator=None,
                 issue_new_refresh_tokens=True,
                 **kwargs):
        super().__init__(
            request_validator,
            issue_new_refresh_tokens=issue_new_refresh_tokens,
            **kwargs)

    def create_token_response(self, request, token_handler):
        """Create a new access token from a refresh_token.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param token_handler: A token handler instance, for example of type
                              oauthlib.oauth2.BearerToken.

        If valid and authorized, the authorization server issues an access
        token as described in `Section 5.1`_. If the request failed
        verification or is invalid, the authorization server returns an error
        response as described in `Section 5.2`_.

        The authorization server MAY issue a new refresh token, in which case
        the client MUST discard the old refresh token and replace it with the
        new refresh token. The authorization server MAY revoke the old
        refresh token after issuing a new refresh token to the client. If a
        new refresh token is issued, the refresh token scope MUST be
        identical to that of the refresh token included by the client in the
        request.

        .. _`Section 5.1`: https://tools.ietf.org/html/rfc6749#section-5.1
        .. _`Section 5.2`: https://tools.ietf.org/html/rfc6749#section-5.2
        """
        headers = self._get_default_headers()
        try:
            log.debug('Validating refresh token request, %r.', request)
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            log.debug('Client error in token request, %s.', e)
            headers.update(e.headers)
            return headers, e.json, e.status_code

        token = token_handler.create_token(request,
                                           refresh_token=self.issue_new_refresh_tokens)

        for modifier in self._token_modifiers:
            token = modifier(token, token_handler, request)

        self.request_validator.save_token(token, request)

        log.debug('Issuing new token to client id %r (%r), %r.',
                  request.client_id, request.client, log_safe(token))
        headers.update(self._create_cors_headers(request))
        return headers, json.dumps(token), 200

    def validate_token_request(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        # REQUIRED. Value MUST be set to "refresh_token".
        if request.grant_type != 'refresh_token':
            raise errors.UnsupportedGrantTypeError(request=request)

        for validator in self.custom_validators.pre_token:
            validator(request)

        if request.refresh_token is None:
            raise errors.InvalidRequestError(
                description='Missing refresh token parameter.',
                request=request)

        # Because refresh tokens are typically long-lasting credentials used to
        # request additional access tokens, the refresh token is bound to the
        # client to which it was issued
        self.validate_client_authentication(request)

        # Ensure client is authorized use of this grant type
        self.validate_grant_type(request)

        # REQUIRED. The refresh token issued to the client.
        log.debug('Validating refresh token %s for client %r.',
                  log_safe(request.refresh_token), request.client)
        if not self.request_validator.validate_refresh_token(
                request.refresh_token, request.client, request):
            log.debug('Invalid refresh token, %s, for client %r.',
                      log_safe(request.refresh_token), request.client)
            raise errors.InvalidGrantError(request=request)

        original_scopes = utils.scope_to_list(
            self.request_validator.get_original_scopes(
                request.refresh_token, request))

        # A refresh token may predate a later withdrawal of part of the
        # resource owner's consent.  The originally issued scopes only prove
        # what was approved when the token was minted; live consent decides
        # what may still be exercised now.  Consent is resolved per token,
        # i.e. per application, so another client of the same subject is
        # unaffected by a withdrawal made for this one.
        consented_scopes = resolve_current_consent_scopes(
            self.request_validator, request.refresh_token, 'refresh_token',
            request)
        original_known = isinstance(original_scopes, (list, tuple, set))
        # Narrowing requires knowing what the grant was issued for.  A
        # validator that returns no original scope collection (``None`` or a
        # non-scope object) is treated like one without live consent, so a
        # legacy record is never silently reduced to no permission at all.
        if consented_scopes is not CONSENT_UNKNOWN and original_known:
            original_list = list(original_scopes)
            granted_scopes = intersect_scopes(
                original_list, consented_scopes)
            request.original_scopes = list(original_list)
        else:
            # No live-consent source: preserve the historical behaviour.
            granted_scopes = original_scopes
            consented_scopes = CONSENT_UNKNOWN

        if request.scope:
            request.scopes = utils.scope_to_list(request.scope)
            within_original = all(
                s in (original_scopes or []) for s in request.scopes)
            if (not within_original
                    and not self.request_validator.is_within_original_scope(
                        request.scopes, request.refresh_token, request)):
                log.debug('Refresh token %s lack requested scopes, %r.',
                          log_safe(request.refresh_token), request.scopes)
                raise errors.InvalidScopeError(request=request)
            if (consented_scopes is not CONSENT_UNKNOWN
                    and any(s not in consented_scopes
                            for s in request.scopes)):
                # A scope outside the live consent may not be re-issued,
                # even on explicit request.  Consent can only narrow the
                # original grant, never add a permission to it.
                log.debug('Refresh token %s asks withdrawn scopes, %r.',
                          log_safe(request.refresh_token), request.scopes)
                raise errors.InvalidScopeError(request=request)
            if consented_scopes is not CONSENT_UNKNOWN:
                retained = intersect_scopes(
                    request.scopes, consented_scopes)
                publish_current_consent(
                    request, consented_scopes, retained)
        else:
            if (consented_scopes is not CONSENT_UNKNOWN
                    and original_scopes and not granted_scopes):
                # Every previously approved scope has been withdrawn; there
                # is no retained permission to mint a token for.
                log.debug('Refresh token %s has no remaining consent.',
                          log_safe(request.refresh_token))
                raise errors.InvalidScopeError(request=request)
            request.scopes = granted_scopes
            if consented_scopes is not CONSENT_UNKNOWN:
                publish_current_consent(
                    request, consented_scopes, granted_scopes)

        for validator in self.custom_validators.post_token:
            validator(request)
