"""
oauthlib.utils
~~~~~~~~~~~~~~

This module contains utility methods used by various parts of the OAuth 2 spec.
"""
import datetime
import os
from urllib.parse import quote, urlparse

from oauthlib.common import urldecode


def list_to_scope(scope):
    """Convert a list of scopes to a space separated string."""
    if isinstance(scope, str) or scope is None:
        return scope
    elif isinstance(scope, (set, tuple, list)):
        return " ".join([str(s) for s in scope])
    else:
        raise ValueError("Invalid scope (%s), must be string, tuple, set, or list." % scope)


def scope_to_list(scope):
    """Convert a space separated string to a list of scopes."""
    if isinstance(scope, (tuple, list, set)):
        return [str(s) for s in scope]
    elif scope is None:
        return None
    else:
        return scope.strip().split(" ")


#: The authorization code has no recoverable scope/protocol provenance because
#: the validator explicitly returned ``None`` for
#: :meth:`RequestValidator.get_authorization_code_scopes`. This is the expected
#: answer for legacy records created before approved scopes were persisted.
SCOPE_PROVENANCE_UNKNOWN = object()

#: The validator does not expose a usable provenance lookup at all (the method
#: is absent or raises :class:`NotImplementedError`). Grants fall back to the
#: scopes populated by ``validate_code``/the current request in this case.
SCOPE_PROVENANCE_NOT_IMPLEMENTED = object()

#: The provenance lookup returned a value that cannot be interpreted as scopes
#: (for example an unfinished mock). Treated like
#: :data:`SCOPE_PROVENANCE_NOT_IMPLEMENTED` for the actual token decision.
SCOPE_PROVENANCE_UNAVAILABLE = object()


def authorization_code_scope_provenance(request_validator, client_id, code,
                                        redirect_uri, request):
    """Resolve the scopes originally approved for an authorization code.

    This is the single entry point used by token dispatch and token issuance
    to decide whether a code exchange belongs to plain OAuth 2.0 or to
    OpenID Connect semantics.

    :returns: A ``tuple`` of scope strings when the validator returned a
        genuine stored scope collection (possibly empty),
        :data:`SCOPE_PROVENANCE_UNKNOWN` when the validator explicitly returned
        ``None`` because a legacy record cannot prove its origin,
        :data:`SCOPE_PROVENANCE_NOT_IMPLEMENTED` when no lookup is implemented,
        or :data:`SCOPE_PROVENANCE_UNAVAILABLE` for an unusable return value.

    Any exception raised by the validator other than
    :class:`NotImplementedError` is propagated, so a validator that wants to
    refuse unproven records may raise an
    :class:`~oauthlib.oauth2.rfc6749.errors.OAuth2Error` (such as
    ``InvalidGrantError``) from its lookup.
    """
    getter = getattr(request_validator,
                     'get_authorization_code_scopes', None)
    if getter is None:
        return SCOPE_PROVENANCE_NOT_IMPLEMENTED
    try:
        value = getter(client_id, code, redirect_uri, request)
    except NotImplementedError:
        return SCOPE_PROVENANCE_NOT_IMPLEMENTED

    if value is None:
        return SCOPE_PROVENANCE_UNKNOWN
    if isinstance(value, str):
        return tuple(scope for scope in (scope_to_list(value) or []) if scope)
    if isinstance(value, (tuple, list, set, frozenset)) and all(
            isinstance(scope, str) for scope in value):
        return tuple(value)
    # A non-container/non-string return value is not a valid provenance
    # result (this includes unfinished mock validators); ignore it instead
    # of treating it as an iterable.
    return SCOPE_PROVENANCE_UNAVAILABLE


def openid_in_code_provenance(provenance, fallback_scopes=None):
    """Decide OIDC semantics from resolved code scope provenance.

    Exact stored scopes are authoritative; an explicitly unknown legacy
    record is conservatively treated as plain OAuth (never upgraded to OIDC);
    and when provenance lookup is unavailable the decision falls back to
    ``fallback_scopes`` (normally ``request.scopes`` as populated by
    ``validate_code``).
    """
    if isinstance(provenance, tuple):
        return 'openid' in provenance
    if provenance is SCOPE_PROVENANCE_UNKNOWN:
        return False
    return bool(fallback_scopes) and 'openid' in fallback_scopes


def params_from_uri(uri):
    params = dict(urldecode(urlparse(uri).query))
    if 'scope' in params:
        params['scope'] = scope_to_list(params['scope'])
    return params


def host_from_uri(uri):
    """Extract hostname and port from URI.

    Will use default port for HTTP and HTTPS if none is present in the URI.
    """
    default_ports = {
        'HTTP': '80',
        'HTTPS': '443',
    }

    parsed = urlparse(uri)
    port = default_ports.get(parsed.scheme.upper()) if parsed.port is None else str(parsed.port)

    return parsed.hostname, port


def escape(u):
    """Escape a string in an OAuth-compatible fashion.

    TODO: verify whether this can in fact be used for OAuth 2

    """
    if not isinstance(u, str):
        raise ValueError('Only unicode objects are escapable.')
    return quote(u.encode('utf-8'), safe=b'~')


def generate_age(issue_time):
    """Generate a age parameter for MAC authentication draft 00."""
    td = datetime.datetime.now() - issue_time
    age = (td.microseconds + (td.seconds + td.days * 24 * 3600)
           * 10 ** 6) / 10 ** 6
    return str(age)


def is_secure_transport(uri):
    """Check if the uri is over ssl."""
    if os.environ.get('OAUTHLIB_INSECURE_TRANSPORT'):
        return True
    return uri.lower().startswith('https://')
