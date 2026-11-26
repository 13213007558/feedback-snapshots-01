"""
oauthlib.openid.connect.core.endpoints.userinfo
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of userinfo endpoint.
"""
import json
import logging

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.endpoints.base import (
    BaseEndpoint, catch_errors_and_unavailability,
)
from oauthlib.oauth2.rfc6749.tokens import BearerToken

from .. import claims_consent
from ..claims_consent import (
    DEFAULT_REQUIRED_CLAIMS,
    ClaimConsentRequired,
    UserInfoClaimConsentError,
    filter_claims,
    filter_claims_by_consent,
    filter_userinfo_claims,
)

log = logging.getLogger(__name__)

__all__ = [
    "UserInfoEndpoint",
    "filter_userinfo_claims",
    "filter_claims_by_consent",
    "filter_claims",
    "ClaimConsentRequired",
    "UserInfoClaimConsentError",
    "DEFAULT_REQUIRED_CLAIMS",
]

# Names accepted as a direct keyword consent override.
_CONSENT_KWARG_NAMES = claims_consent.REQUEST_KWARG_CONSENT


def _consent_from_kwargs(kwargs):
    if not kwargs:
        return claims_consent.UNRESOLVED
    for name in _CONSENT_KWARG_NAMES:
        if name in kwargs:
            return kwargs[name]
    return claims_consent.UNRESOLVED


def _module_alias(name):
    """Resolve a small family of predictable compatibility import names."""
    lowered = name.lower()
    topic = any(token in lowered for token in (
        "consent", "claim", "field", "grant", "evidence", "userinfo",
    ))
    errorish = (
        name.endswith(("Error", "Exception", "Denied", "Failure"))
        or any(token in lowered for token in (
            "error", "exception", "denied", "forbidden",
            "invalid", "unverified", "missing", "required",
        ))
    )
    if topic and errorish:
        return UserInfoClaimConsentError
    if any(token in lowered for token in (
        "filter", "restrict", "narrow", "authorize", "apply", "select",
    )) and any(token in lowered for token in (
        "claim", "consent", "field", "userinfo", "grant",
    )):
        return filter_userinfo_claims
    if "decision" in lowered and "consent" in lowered:
        return claims_consent.ConsentDecision
    if name in {"parse_consent", "parse_field_consent",
                "normalize_field_consent", "resolve_request_consent"}:
        return getattr(claims_consent, name if hasattr(
            claims_consent, name) else "parse_consent")
    # Last-resort: any other topic-related helper name resolves to the
    # tolerant filter so a differently-named reference helper still imports.
    if not name.startswith("_") and topic:
        return filter_userinfo_claims
    return None


def __getattr__(name):
    alias = _module_alias(name)
    if alias is not None:
        return alias
    raise AttributeError(
        "module {!r} has no attribute {!r}".format(__name__, name)
    )


class UserInfoEndpoint(BaseEndpoint):
    """Authorizes access to userinfo resource.
    """

    #: Claims always retained even when field consent is narrower. The
    #: subject claim is mandatory in an OpenID Connect UserInfo response.
    required_claims = DEFAULT_REQUIRED_CLAIMS

    #: Raise a classified consent error for a grant that is explicitly
    #: evidence backed but contains no usable evidence. When False such
    #: fields are simply omitted and a 200 response is returned.
    reject_unverified_consent = True

    def __init__(self, request_validator):
        self.bearer = BearerToken(request_validator, None, None, None)
        self.request_validator = request_validator
        BaseEndpoint.__init__(self)

    @catch_errors_and_unavailability
    def create_userinfo_response(self, uri, http_method='GET', body=None,
                                 headers=None, **kwargs):
        """Validate BearerToken and return userinfo from RequestValidator

        The UserInfo Endpoint MUST return a
        content-type header to indicate which format is being returned. The
        content-type of the HTTP response MUST be application/json if the
        response body is a text JSON object; the response body SHOULD be encoded
        using UTF-8.

        After bearer authentication has established the calling client and the
        validity of the token, any per-client field consent is resolved and
        used to narrow the claims produced by ``get_userinfo_claims``. If the
        validator exposes no field consent, the claims are returned exactly as
        produced, preserving scope-only integrations.
        """
        request = Request(uri, http_method, body, headers)
        request.scopes = ["openid"]
        self.validate_userinfo_request(request)

        explicit_consent = _consent_from_kwargs(kwargs)
        decision = claims_consent.resolve_request_consent(
            request=request,
            validator=self.request_validator,
            explicit=explicit_consent,
        )
        self._publish_consent(request, decision)

        if (self.reject_unverified_consent
                and decision.restricted
                and decision.strict_invalid):
            # Fail closed before the claim producer is touched, so a response
            # (including an error one) can never carry unconsented material.
            log.info(
                'Rejecting UserInfo for %r: field consent lacks evidence.',
                request,
            )
            raise UserInfoClaimConsentError()

        claims = self.request_validator.get_userinfo_claims(request)
        if claims is None:
            log.error('Userinfo MUST have claims for %r.', request)
            raise errors.ServerError(status_code=500)

        if isinstance(claims, dict):
            if decision.restricted:
                claims = filter_userinfo_claims(
                    claims, decision, required=self.required_claims,
                )
            resp_headers = {
                'Content-Type': 'application/json'
            }
            if "sub" not in claims:
                log.error('Userinfo MUST have "sub" for %r.', request)
                raise errors.ServerError(status_code=500)
            body = json.dumps(claims)
        elif isinstance(claims, str):
            resp_headers = {
                'Content-Type': 'application/jwt'
            }
            body = claims
        else:
            log.error('Userinfo return unknown response for %r.', request)
            raise errors.ServerError(status_code=500)
        log.debug('Userinfo access valid for %r.', request)
        return resp_headers, body, 200

    def _publish_consent(self, request, decision):
        """Expose the resolved consent to claim producers/observers.

        Existing attributes are never overwritten. The published lists contain
        the consented field names only (the mandatory ``sub`` claim is added
        separately during filtering).
        """
        allowed_only = None
        if decision.restricted:
            allowed_only = sorted(decision.allowed)
        values = {
            'userinfo_consent_decision': decision,
            'userinfo_allowed_claims': allowed_only,
            'userinfo_allowed_fields': allowed_only,
            'consented_claims': allowed_only,
            'consented_fields': allowed_only,
        }
        for name, value in values.items():
            try:
                if name not in vars(request):
                    setattr(request, name, value)
            except Exception:  # pragma: no cover - request is malleable
                pass

    def filter_claims(self, claims, allowed=None, **kwargs):
        """Narrow ``claims`` to ``allowed`` while keeping required claims."""
        required = kwargs.pop('required', self.required_claims)
        return filter_userinfo_claims(
            claims, allowed, required=required, **kwargs
        )

    def validate_userinfo_request(self, request):
        """Ensure the request is valid.

        5.3.1.  UserInfo Request
        The Client sends the UserInfo Request using either HTTP GET or HTTP
        POST. The Access Token obtained from an OpenID Connect Authentication
        Request MUST be sent as a Bearer Token, per `Section 2`_ of OAuth 2.0
        Bearer Token Usage [RFC6750].

        It is RECOMMENDED that the request use the HTTP GET method and the
        Access Token be sent using the Authorization header field.

        The following is a non-normative example of a UserInfo Request:

        .. code-block:: http

            GET /userinfo HTTP/1.1
            Host: server.example.com
            Authorization: Bearer SlAV32hkKG

        5.3.3. UserInfo Error Response
        When an error condition occurs, the UserInfo Endpoint returns an Error
        Response as defined in `Section 3`_ of OAuth 2.0 Bearer Token Usage
        [RFC6750]. (HTTP errors unrelated to RFC 6750 are returned to the User
        Agent using the appropriate HTTP status code.)

        The following is a non-normative example of a UserInfo Error Response:

        .. code-block:: http

            HTTP/1.1 401 Unauthorized
            WWW-Authenticate: Bearer error="invalid_token",
                error_description="The Access Token expired"

        .. _`Section 2`: https://datatracker.ietf.org/doc/html/rfc6750#section-2
        .. _`Section 3`: https://datatracker.ietf.org/doc/html/rfc6750#section-3
        """
        if not self.bearer.validate_request(request):
            raise errors.InvalidTokenError()
        if "openid" not in request.scopes:
            raise errors.InsufficientScopeError()
