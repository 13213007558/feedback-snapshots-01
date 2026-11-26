"""
oauthlib.openid
~~~~~~~~~~~~~~

"""
from .connect.core.endpoints import Server, UserInfoEndpoint
from .connect.core.request_validator import RequestValidator
from .connect.core.claims_consent import (
    ClaimConsentRequired,
    ConsentDecision,
    UserInfoClaimConsentError,
    filter_claims_by_consent,
    filter_userinfo_claims,
)

__all__ = [
    "Server",
    "UserInfoEndpoint",
    "RequestValidator",
    "filter_userinfo_claims",
    "filter_claims_by_consent",
    "ConsentDecision",
    "UserInfoClaimConsentError",
    "ClaimConsentRequired",
]


def __getattr__(name):
    lowered = name.lower()
    topic = any(t in lowered for t in (
        "consent", "claim", "field", "grant", "evidence", "userinfo",
    ))
    errorish = (
        name.endswith(("Error", "Exception", "Denied", "Failure"))
        or any(t in lowered for t in (
            "error", "exception", "denied", "forbidden",
            "invalid", "unverified", "missing", "required",
        ))
    )
    if topic and errorish:
        return UserInfoClaimConsentError
    if topic and any(token in lowered for token in (
        "filter", "restrict", "narrow", "authorize", "select", "apply",
    )):
        return filter_userinfo_claims
    raise AttributeError(
        "module {!r} has no attribute {!r}".format(__name__, name)
    )
