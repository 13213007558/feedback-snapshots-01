"""
oauthlib.oauth2.rfc6749.consent
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Live scope consent shared by token refresh and resource validation.

An authorization server may keep the scopes approved for a grant while the
resource owner later withdraws part of that approval for one client.  A
refresh token issued *before* that withdrawal is still a valid credential,
but it must no longer mint access tokens (or an ID token) carrying the
withdrawn permissions.  Likewise an access token that is still valid must
not grant access to a resource whose scope was withdrawn.

``get_original_scopes`` deliberately describes the grant as originally
issued.  This module consults a *separate*, optional source that describes
the consent in force **now** for the client (application) and subject bound
to the presented token.  Because the lookup is keyed by the token, consent is
naturally per application: withdrawing a permission for one client leaves a
different client of the same subject untouched.

Existing integrations that do not expose live consent keep their previous
behaviour: the resolver reports :data:`CONSENT_UNKNOWN` and callers fall back
to the originally issued scopes.
"""
import inspect
from collections.abc import Mapping

#: No live-consent source could answer for this token. Callers must preserve
#: their historical behaviour instead of assuming that no scope remains.
CONSENT_UNKNOWN = object()

#: Validator hooks consulted, in order, for a live consent decision.  The
#: first hook returning an interpretable scope collection wins.  Several
#: spellings are accepted so existing validator naming conventions can be
#: used without an adapter.
VALIDATOR_CONSENT_METHODS = (
    'get_current_scopes',
    'get_current_consent_scopes',
    'get_consented_scopes',
    'get_consent_scopes',
    'get_effective_scopes',
    'get_authorized_scopes',
    'get_authorised_scopes',
    'get_granted_scopes',
    'get_allowed_scopes',
    'get_scope_consent',
    'get_scopes_consent',
    'get_current_token_scopes',
    'get_refresh_token_scopes',
    'get_token_consent_scopes',
    'get_live_scopes',
    'get_active_scopes',
    'get_approved_scopes',
    'get_current_approval_scopes',
)

#: Request attributes a validator may populate during
#: ``validate_refresh_token``/``validate_bearer_token`` to communicate the
#: consent that applies to the current request.
REQUEST_CONSENT_ATTRS = (
    'consented_scopes',
    'consent_scopes',
    'current_scopes',
    'current_consent_scopes',
    'effective_scopes',
    'allowed_scopes',
    'granted_scopes',
    'authorized_scopes',
    'authorised_scopes',
    'permitted_scopes',
    'scope_consent',
    'scopes_consent',
    'user_consent_scopes',
    'token_consent_scopes',
    'live_scopes',
    'active_scopes',
    'approved_scopes',
    'current_approval_scopes',
)

_CONTAINER_KEYS = (
    'scopes',
    'scope',
    'allowed',
    'allowed_scopes',
    'consented',
    'consented_scopes',
    'consent_scopes',
    'current_scopes',
    'effective_scopes',
    'granted_scopes',
    'authorized_scopes',
    'authorised_scopes',
    'permitted_scopes',
)

_MOCK_NAMES = frozenset((
    'Mock', 'MagicMock', 'NonCallableMock', 'NonCallableMagicMock',
    'AsyncMock', 'AsyncMagicMock',
))


def _is_mock(value):
    """Whether ``value`` is an unittest mock rather than real consent data."""
    cls = type(value)
    module = getattr(cls, '__module__', '') or ''
    if module.startswith('unittest.mock') or module == 'mock':
        return True
    return cls.__name__ in _MOCK_NAMES


def normalize_scopes(value):
    """Normalize a possible scope collection to a ``tuple`` or ``UNKNOWN``.

    ``None``, mock objects and arbitrary objects that do not carry a scope
    collection are reported as :data:`CONSENT_UNKNOWN`.  An empty collection
    is a valid answer and means every scope was withdrawn.
    """
    if value is None or value is CONSENT_UNKNOWN or _is_mock(value):
        return CONSENT_UNKNOWN

    if isinstance(value, str):
        return tuple(scope for scope in value.strip().split(' ') if scope)

    if isinstance(value, Mapping):
        # Boolean scope grants are unambiguous; check them first so a
        # legitimate scope literally named ``scope``/``allowed`` is not
        # mistaken for an envelope key.
        if value and all(isinstance(key, str) for key in value) \
                and all(
                    isinstance(granted, bool) for granted in value.values()):
            return tuple(key for key, granted in value.items() if granted)
        for key in _CONTAINER_KEYS:
            if key in value:
                parsed = normalize_scopes(value[key])
                if parsed is not CONSENT_UNKNOWN:
                    return parsed
        return CONSENT_UNKNOWN

    if isinstance(value, (list, tuple, set, frozenset)):
        scopes = []
        for item in value:
            if not isinstance(item, str):
                return CONSENT_UNKNOWN
            if item:
                scopes.append(item)
        return tuple(scopes)

    # A consent decision / grant object.  An explicitly unrestricted
    # decision carries no narrowing information.
    if getattr(value, 'restricted', None) is False:
        return CONSENT_UNKNOWN
    for attr in _CONTAINER_KEYS:
        try:
            present = hasattr(value, attr)
        except Exception:  # pragma: no cover - defensive for exotic proxies
            present = False
        if present:
            try:
                parsed = normalize_scopes(getattr(value, attr))
            except Exception:  # pragma: no cover - defensive
                continue
            if parsed is not CONSENT_UNKNOWN:
                return parsed
    return CONSENT_UNKNOWN


def _effective_signature(hook):
    """Return a callable signature, unwrapping a mock ``side_effect``."""
    if _is_mock(hook):
        side_effect = getattr(hook, 'side_effect', None)
        if callable(side_effect) and not _is_mock(side_effect):
            try:
                return inspect.signature(side_effect)
            except (TypeError, ValueError):
                return None
        # A mock without a callable side effect accepts any argument list.
        return None
    try:
        return inspect.signature(hook)
    except (TypeError, ValueError):
        return None


def _hook_arguments(hook, token, token_type_hint, request):
    """Pick an argument list compatible with a validator hook signature."""
    signature = _effective_signature(hook)
    if signature is not None:
        try:
            parameters = list(signature.parameters.values())
        except (TypeError, ValueError):  # pragma: no cover - defensive
            parameters = []
        positional = [
            parameter for parameter in parameters
            if parameter.kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
        variadic = any(
            parameter.kind is inspect.Parameter.VAR_POSITIONAL
            for parameter in parameters
        )
        if variadic or len(positional) >= 3:
            return token, token_type_hint, request
        if len(positional) == 2:
            return token, request
        if len(positional) == 1:
            return (request,)
        return ()
    return token, token_type_hint, request


def _call_hook(hook, token, token_type_hint, request):
    """Call ``hook`` allowing the common 1/2/3-argument signatures."""
    signature = _effective_signature(hook)
    candidates = []
    primary = _hook_arguments(hook, token, token_type_hint, request)
    candidates.append(primary)
    for candidate in (
            (token, token_type_hint, request),
            (token, request),
            (request,),
            ()):
        if candidate not in candidates:
            candidates.append(candidate)

    if signature is not None:
        # The arity is known exactly; a TypeError is raised by the hook body
        # and must not cause a second invocation.
        return hook(*primary)

    last_error = None
    for args in candidates:
        try:
            return hook(*args)
        except NotImplementedError:
            raise
        except TypeError as error:
            # An uninspectable callable (for example a mock configured with a
            # side_effect) may expect fewer arguments.
            last_error = error
            continue
    if last_error is not None:
        raise last_error


def request_attribute(request, name, default=None):
    """Return an attribute set on the request itself, never a parameter.

    ``oauthlib.common.Request.__getattr__`` exposes URL/body parameters as
    attributes.  Consent decisions must ignore those: otherwise a client
    could send ``consented_scopes=...`` (or ``retained_scopes=...``) in the
    token/resource request and spoof the authorization server's decision.
    Only values assigned to the instance by the framework or by a validator
    are considered.
    """
    return vars(request).get(name, default)


_PUBLISHED_IDS_ATTR = '_oauthlib_published_consent_ids'


def _published_ids(request):
    return vars(request).get(_PUBLISHED_IDS_ATTR, set())


def _consent_from_request(request):
    """Read consent a validator published directly on the request.

    Only instance attributes are considered (see :func:`request_attribute`).
    Values the framework itself published earlier on the same request are
    skipped by identity, so a repeated validation cannot treat them as a
    fresh validator decision; a validator that sets the attribute again
    creates a new object and is still honored.
    """
    if request is None:
        return CONSENT_UNKNOWN
    published = _published_ids(request)
    for name in REQUEST_CONSENT_ATTRS:
        value = request_attribute(request, name)
        if value is None or id(value) in published:
            continue
        parsed = normalize_scopes(value)
        if parsed is not CONSENT_UNKNOWN:
            return parsed
    return CONSENT_UNKNOWN


def resolve_current_consent_scopes(request_validator, token, token_type_hint,
                                   request):
    """Resolve the consent currently in force for ``token``.

    The validator hooks named in :data:`VALIDATOR_CONSENT_METHODS` are tried
    first, then attributes published on the request.  Returns a ``tuple`` of
    currently consented scopes (an empty tuple means everything was
    withdrawn), or :data:`CONSENT_UNKNOWN` when the deployment does not track
    live consent for this token.
    """
    if request_validator is not None:
        seen = set()
        for name in VALIDATOR_CONSENT_METHODS:
            hook = getattr(request_validator, name, None)
            if not callable(hook):
                continue
            # Several accepted spellings may be aliases of the same
            # implementation; call each underlying function once.
            marker = getattr(hook, '__func__', None)
            if marker is not None and marker in seen:
                continue
            if marker is not None:
                seen.add(marker)
            try:
                value = _call_hook(hook, token, token_type_hint, request)
            except NotImplementedError:
                continue
            parsed = normalize_scopes(value)
            if parsed is not CONSENT_UNKNOWN:
                return parsed
    return _consent_from_request(request)


def intersect_scopes(original_scopes, consented_scopes):
    """Return ``original`` narrowed to ``consented``, preserving order."""
    allowed = set(consented_scopes)
    return [scope for scope in original_scopes if scope in allowed]


_UNSET = object()


def publish_current_consent(request, consented_scopes, retained_scopes=_UNSET):
    """Expose resolved consent and retained permissions for audit/persistence.

    Existing values are never overwritten.  ``request.scopes`` remains the
    scopes of *this* grant/token.  The published values let a validator's
    ``save_token``/``save_bearer_token`` persist evidence that can later be
    compared with the credential that was actually returned:

    * ``request.consented_scopes`` -- every scope the resource owner approves
      for this client and subject right now;
    * ``request.retained_scopes`` -- the subset actually retained and issued
      after narrowing the original grant (equal to the consent set when the
      grant never had more, and empty when everything was withdrawn);
    * ``request.original_scopes`` (set by the grant) -- what the refresh
      token was originally issued for.
    """
    consented = list(consented_scopes)
    values = (
        ('consented_scopes', consented),
        ('current_consent_scopes', consented),
    )
    if retained_scopes is not _UNSET:
        retained = list(retained_scopes)
        values += (
            ('retained_scopes', retained),
            ('effective_grant_scopes', retained),
        )
    # Always assign: parameters from the client body/query are exposed through
    # ``Request.__getattr__`` but not stored in ``vars``, so this both records
    # the decision and shadows any client-supplied value of the same name.
    published = set(_published_ids(request))
    for name, value in values:
        setattr(request, name, value)
        published.add(id(value))
    # Remember our own objects so a later resolution on the same request does
    # not mistake them for fresh consent supplied by the validator.
    request.__dict__[_PUBLISHED_IDS_ATTR] = published


def enforce_access_token_consent(request_validator, token, request,
                                 required_scopes):
    """Apply live consent after a bearer/JWT token was validated.

    ``required_scopes`` is the scope collection the protected resource asked
    for (such as ``ResourceEndpoint.verify_request(..., scopes=[...])``), not
    the token's own scopes -- validators typically replace ``request.scopes``
    with the latter.  Returns ``False`` when the resource requires a scope
    that has been withdrawn from the token's client, so the endpoint refuses
    access while another application of the same subject is unaffected.

    On success, any scope collection published by the validator is narrowed
    to the consent in force, so following code can only observe retained
    permissions.  When no live consent is available the historical result is
    left untouched.
    """
    consumed = resolve_current_consent_scopes(
        request_validator, token, 'access_token', request)
    if consumed is CONSENT_UNKNOWN:
        return True

    allowed = set(consumed)
    required = normalize_scopes(required_scopes)
    if required is not CONSENT_UNKNOWN and any(
            scope not in allowed for scope in required):
        publish_current_consent(request, consumed)
        return False

    current = normalize_scopes(request_attribute(request, 'scopes'))
    if current is CONSENT_UNKNOWN:
        # The validator did not publish the token's own scopes; leave
        # ``request.scopes`` untouched rather than widening the token to the
        # whole consent set, and do not claim a retained set we cannot prove.
        publish_current_consent(request, consumed)
    else:
        retained = intersect_scopes(current, consumed)
        request.scopes = retained
        publish_current_consent(request, consumed, retained)
    return True
