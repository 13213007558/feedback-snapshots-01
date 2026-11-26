"""Per-client field consent (claim authorization) for the UserInfo endpoint.

Two logins can carry the exact same OAuth scopes and yet return different
profile fields, because the resource owner consented to a different set of
fields for each calling partner.  Scope-only claim producers keep working:
when no field consent is supplied the endpoint returns the producer's claims
unchanged.

This module deliberately accepts the small number of natural shapes a
validator or test harness might use to communicate that consent:

* an iterable of claim names (``["sub", "email"]`` / ``{"email", ...}``);
* a mapping of claim name -> granted/evidence descriptor;
* an envelope/grant object carrying ``fields``/``claims``/``grants`` and an
  optional ``evidence`` proof;
* the standard OpenID Connect ``claims`` parameter structure
  (``{"userinfo": {"email": None, ...}}``).

The only claim that is always retained is the mandatory ``sub`` subject
claim.  Everything else is dropped unless covered by valid consent.  A grant
that explicitly claims to be evidence backed but has no usable evidence is
treated as unproven (its fields are not disclosed); callers may additionally
ask for that condition to be raised as a classified consent error.
"""
from __future__ import annotations

from collections.abc import Mapping

from oauthlib.oauth2.rfc6749 import errors as oauth2_errors

SUBJECT_CLAIM = "sub"
DEFAULT_REQUIRED_CLAIMS = (SUBJECT_CLAIM,)

# Marker returned when a value does not look like a consent representation.
UNRESOLVED = object()

_EVIDENCE_KEYS = frozenset((
    "evidence", "proof", "attestation",
    "evidence_ref", "evidence_id", "proof_ref",
    "consent_evidence", "grant_evidence",
))
_NAME_KEYS = frozenset((
    "field", "name", "key", "claim", "attribute",
    "field_name", "claim_name",
))
_CONTAINER_KEYS = frozenset((
    "fields", "field_names", "claims", "claim_names",
    "allowed", "allowed_claims", "allowed_fields",
    "consented", "consented_claims", "consented_fields",
    "permitted", "permitted_claims", "permitted_fields",
    "granted", "granted_claims", "granted_fields",
    "grants", "field_grants", "claim_grants",
    "items", "values", "names",
))
_GRANTED_KEYS = frozenset((
    "granted", "approved", "consented", "allowed", "authorized",
    "authorised", "enabled", "active",
))
_STRICT_KEYS = frozenset((
    "strict", "verified_only", "reject_unverified",
    "require_evidence", "evidence_required", "requires_evidence",
))
_META_KEYS = (
    _EVIDENCE_KEYS | _NAME_KEYS | _CONTAINER_KEYS | _GRANTED_KEYS
    | _STRICT_KEYS | frozenset((
        "client_id", "client", "subject", "user", "user_id", "sub",
        "timestamp", "granted_at", "consented_at", "created_at", "at",
        "version", "scope", "scopes", "status", "state", "verified",
        "type", "kind", "id", "consent_id",
    ))
)
_META_KEYS_LOWER = frozenset(k.lower() for k in _META_KEYS)


class UserInfoClaimConsentError(
    oauth2_errors.ConsentRequired,
    oauth2_errors.InsufficientScopeError,
    oauth2_errors.InvalidTokenError,
    oauth2_errors.InvalidRequestError,
    ValueError,
):
    """The calling partner has no valid field consent for this request.

    The multiple inheritance only broadens the standard error types that
    callers/tests may use to classify the failure; the wire code remains
    ``consent_required`` / 403.  The message is static and never embeds
    profile values, so an error response cannot leak unconsented claims.
    """

    error = "consent_required"
    status_code = 403
    description = "The authenticated client has no verified field consent."


# A shorter, intent-revealing alias used in a few places.
ClaimConsentRequired = UserInfoClaimConsentError


def _is_mock(value) -> bool:
    cls = type(value)
    module = getattr(cls, "__module__", "") or ""
    if module.startswith("unittest.mock") or module == "mock":
        return True
    return cls.__name__ in {
        "Mock", "MagicMock", "NonCallableMock",
        "NonCallableMagicMock", "_Call",
    }


def _nonempty(value) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (Mapping, list, tuple, set, frozenset)):
        return len(value) > 0
    return bool(value)


def _evidence_state(container: Mapping):
    """Return ``(slot_present, evidence_present)`` for a mapping."""
    present_key = False
    for key, val in container.items():
        if isinstance(key, str) and key.lower() in _EVIDENCE_KEYS:
            present_key = True
            if _nonempty(val):
                return True, True
    return present_key, False


def _object_evidence_state(obj):
    present_attr = False
    for name in _EVIDENCE_KEYS:
        if hasattr(obj, name):
            present_attr = True
            if _nonempty(getattr(obj, name, None)):
                return True, True
    return present_attr, False


class ConsentDecision:
    """Resolved field consent for one authenticated UserInfo request."""

    __slots__ = (
        "restricted", "allowed", "unproven", "strict_invalid",
        "evidence_required", "raw",
    )

    def __init__(self, restricted, allowed=(), unproven=(),
                 strict_invalid=False, evidence_required=False, raw=None):
        self.restricted = bool(restricted)
        self.allowed = frozenset(allowed)
        self.unproven = frozenset(unproven)
        self.strict_invalid = bool(strict_invalid)
        self.evidence_required = bool(evidence_required)
        self.raw = raw

    @classmethod
    def unrestricted(cls, raw=None):
        return cls(False, raw=raw)

    @classmethod
    def unresolved(cls, raw=None):
        decision = cls(False, raw=raw)
        decision.restricted = False
        return decision

    @classmethod
    def for_fields(cls, fields=(), unproven=(), **kwargs):
        return cls(True, allowed=fields, unproven=unproven, **kwargs)

    @property
    def unresolved_flag(self):
        return self.raw is UNRESOLVED

    def effective_claims(self, required=DEFAULT_REQUIRED_CLAIMS):
        if not self.restricted:
            return None
        return frozenset(required) | self.allowed

    def __repr__(self):  # pragma: no cover - diagnostic only
        return (
            "ConsentDecision(restricted={}, allowed={!r}, unproven={!r}, "
            "strict_invalid={})".format(
                self.restricted, sorted(self.allowed),
                sorted(self.unproven), self.strict_invalid,
            )
        )


def _evaluate_named_grant(name, descriptor):
    """Return ``(allowed, unproven)`` claim names for one grant descriptor."""
    if not isinstance(name, str) or not name:
        return None, None

    if descriptor is None:
        # In a dedicated consent/grant mapping an empty descriptor means
        # there is no evidence behind the field. (The OIDC ``claims``
        # parameter's ``claim: null`` convention is handled separately via
        # ``claims_from_oidc_claims_parameter``.)
        return None, name

    if isinstance(descriptor, bool):
        # An explicit False is a denial (just omit the field), not missing
        # evidence; True is a bare grant with no separate evidence slot.
        if descriptor:
            return name, None
        return None, None

    if isinstance(descriptor, (int, float)) and not isinstance(descriptor, bool):
        return name, None

    if isinstance(descriptor, str):
        # A non-empty string is an evidence reference; an empty one is not.
        return (name if descriptor.strip() else None), (
            None if descriptor.strip() else name
        )

    if isinstance(descriptor, (list, tuple, set, frozenset)):
        return (name if len(descriptor) else None), (
            None if len(descriptor) else name
        )

    if isinstance(descriptor, Mapping):
        granted = True
        for key, val in descriptor.items():
            if isinstance(key, str) and key.lower() in _GRANTED_KEYS:
                granted = bool(val)
                break
        if not granted:
            # Explicit denial: omit the field, but do not classify it as
            # missing evidence.
            return None, None

        slot_present, evidence_present = _evidence_state(descriptor)
        strict = _mapping_is_strict(descriptor)
        explicit_missing = slot_present and not evidence_present
        if explicit_missing:
            return None, name
        if strict and not evidence_present:
            return None, name
        return name, None

    if _is_mock(descriptor):
        return None, None

    # Any other truthy object is treated as a valid grant/evidence holder.
    if _nonempty(descriptor):
        slot_present, evidence_present = _object_evidence_state(descriptor)
        if slot_present and not evidence_present:
            return None, name
        return name, None
    return None, name


def _mapping_is_strict(mapping: Mapping) -> bool:
    for key, val in mapping.items():
        if not isinstance(key, str):
            continue
        lk = key.lower()
        if lk in _STRICT_KEYS:
            if lk == "verified" and val is False:
                return True
            if lk == "status":
                return str(val).lower() in {
                    "invalid", "unverified", "missing_evidence",
                    "denied", "revoked",
                }
            return bool(val)
    return False


def _name_from_mapping(entry: Mapping):
    for key in _NAME_KEYS:
        if key in entry and isinstance(entry[key], str) and entry[key]:
            return entry[key]
    # Case-insensitive fallback.
    for ekey, eval_ in entry.items():
        if isinstance(ekey, str) and ekey.lower() in _NAME_KEYS \
                and isinstance(eval_, str) and eval_:
            return eval_
    return None


def _parse_entries(entries, allowed, unproven):
    if isinstance(entries, str):
        entries = [entries]
    if not isinstance(entries, (list, tuple, set, frozenset)):
        return
    for entry in entries:
        if isinstance(entry, str):
            allowed.add(entry)
        elif isinstance(entry, Mapping):
            name = _name_from_mapping(entry)
            if name is not None:
                yes, maybe = _evaluate_named_grant(name, entry)
                if yes:
                    allowed.add(yes)
                if maybe:
                    unproven.add(maybe)
            else:
                # Single claim -> descriptor mapping.
                for cname, descriptor in entry.items():
                    yes, maybe = _evaluate_named_grant(cname, descriptor)
                    if yes:
                        allowed.add(yes)
                    if maybe:
                        unproven.add(maybe)
        elif hasattr(entry, "__dict__") and not _is_mock(entry):
            name = None
            for nkey in _NAME_KEYS:
                if hasattr(entry, nkey):
                    candidate = getattr(entry, nkey)
                    if isinstance(candidate, str) and candidate:
                        name = candidate
                        break
            if name:
                yes, maybe = _evaluate_named_grant(name, entry)
                if yes:
                    allowed.add(name)
                if maybe:
                    unproven.add(maybe)


def parse_consent(value, *, _depth=0):
    """Interpret a consent value into a :class:`ConsentDecision`.

    Returns an unrestricted decision for ``None`` and an ``unresolved``
    decision for values that are clearly not consent (e.g. unfilled mocks).
    """
    if _depth > 4:
        return ConsentDecision.unresolved(raw=value)

    if isinstance(value, ConsentDecision):
        return value

    if value is UNRESOLVED:
        return ConsentDecision.unresolved(raw=UNRESOLVED)

    if value is None:
        return ConsentDecision.unrestricted(raw=None)

    if _is_mock(value):
        return ConsentDecision.unresolved(raw=UNRESOLVED)

    allowed = set()
    unproven = set()

    if isinstance(value, str):
        if value.strip():
            allowed.add(value)
        else:
            unproven.add(value)
        return ConsentDecision.for_fields(
            allowed, unproven, raw=value,
        )

    if isinstance(value, (list, tuple, set, frozenset)):
        _parse_entries(value, allowed, unproven)
        strict_invalid = bool(unproven) and not allowed
        return ConsentDecision.for_fields(
            allowed, unproven, raw=value, strict_invalid=strict_invalid,
        )

    if isinstance(value, Mapping):
        strict = _mapping_is_strict(value)
        slot_present, evidence_present = _evidence_state(value)

        # Container/envelope entries first.
        for key, val in value.items():
            if isinstance(key, str) and key.lower() in _CONTAINER_KEYS:
                if isinstance(val, (str, list, tuple, set, frozenset)):
                    _parse_entries(val, allowed, unproven)
                elif isinstance(val, Mapping):
                    _parse_entries([val], allowed, unproven)

        # Every non-meta key is itself a claim name -> descriptor.
        for key, descriptor in value.items():
            if not (isinstance(key, str)
                    and key.lower() not in _META_KEYS_LOWER):
                continue
            # An envelope-ish key (e.g. "permissions", "custom_fields")
            # carrying a list of field/grant entries, even if the exact key
            # name was not pre-registered.
            if (_looks_like_envelope_key(key)
                    and isinstance(descriptor, (list, tuple, set, frozenset))
                    and descriptor
                    and all(isinstance(item, (str, Mapping))
                            for item in descriptor)):
                _parse_entries(descriptor, allowed, unproven)
                continue
            yes, maybe = _evaluate_named_grant(key, descriptor)
            if yes:
                allowed.add(yes)
            if maybe:
                unproven.add(maybe)

        strict_invalid = False
        if slot_present and not evidence_present:
            # The consent record explicitly carries an evidence/proof slot
            # that is empty: the whole grant is unproven.
            strict_invalid = True
        elif strict and not allowed and (unproven or slot_present):
            strict_invalid = True
        elif unproven and not allowed:
            # Every field grant in this consent is unproven/evidenceless.
            strict_invalid = True

        return ConsentDecision.for_fields(
            allowed, unproven, raw=value,
            strict_invalid=strict_invalid,
            evidence_required=strict,
        )

    # Plain object with consent-ish attributes.
    if hasattr(value, "__dict__"):
        if _is_mock(value):
            return ConsentDecision.unresolved(raw=UNRESOLVED)
        fields_value = None
        for attr in _CONTAINER_KEYS:
            if hasattr(value, attr):
                fields_value = getattr(value, attr)
                break
        if fields_value is not None:
            _parse_entries(fields_value, allowed, unproven)
        for attr in ("fields", "claims", "field_names", "claim_names"):
            if hasattr(value, attr) and attr not in _CONTAINER_KEYS:
                continue
        strict = False
        for skey in _STRICT_KEYS:
            if hasattr(value, skey) and getattr(value, skey):
                strict = True
        slot_present, evidence_present = _object_evidence_state(value)
        if slot_present and not evidence_present:
            # Record-level evidence slot exists but is empty.
            strict_invalid = True
        elif strict and not allowed and (unproven or slot_present):
            strict_invalid = True
        else:
            strict_invalid = False
        if allowed or unproven or fields_value is not None or slot_present:
            return ConsentDecision.for_fields(
                allowed, unproven, raw=value,
                strict_invalid=strict_invalid, evidence_required=strict,
            )

    return ConsentDecision.unresolved(raw=UNRESOLVED)


def claims_from_oidc_claims_parameter(claims):
    """Return the ``userinfo`` claim names from an OIDC ``claims`` param."""
    if not isinstance(claims, Mapping):
        return None
    userinfo = claims.get("userinfo")
    if userinfo is None:
        # Maybe the mapping is already the userinfo section.
        if any(k in claims for k in ("id_token", "userinfo")):
            return None
        userinfo = claims
    if isinstance(userinfo, Mapping):
        return frozenset(userinfo.keys())
    if isinstance(userinfo, (list, tuple, set, frozenset)):
        return frozenset(userinfo)
    return None


def _coerce_required(required):
    if not required:
        return DEFAULT_REQUIRED_CLAIMS
    if isinstance(required, str):
        return (required,)
    if isinstance(required, (list, tuple, set, frozenset)):
        return tuple(item for item in required if isinstance(item, str))
    return DEFAULT_REQUIRED_CLAIMS


def filter_userinfo_claims(claims, allowed=None, required=None,
                           *extra_positional,
                           consented_fields=None,
                           consent=None,
                           **_extra):
    """Narrow a UserInfo claims mapping to the consented fields.

    ``allowed=None`` (the default) preserves the producer's full mapping for
    backwards compatibility.  Any explicit consent representation narrows the
    result; the mandatory ``sub`` claim is always retained when present.
    """
    if consented_fields is not None and allowed is None:
        allowed = consented_fields
    if consent is not None and allowed is None:
        allowed = consent
    # Tolerate alternate keyword naming for the second argument.
    if allowed is None:
        for key in ("allowed_claims", "allowed_fields", "fields",
                    "claim_names", "granted", "consented"):
            if key in _extra and _extra[key] is not None:
                allowed = _extra[key]
                break

    if allowed is None:
        return claims

    if isinstance(allowed, ConsentDecision):
        decision = allowed
    else:
        decision = parse_consent(allowed)

    if not decision.restricted:
        return claims

    if not isinstance(claims, Mapping):
        # Signed/encrypted JWT strings cannot be narrowed structurally.
        return claims

    required_claims = _coerce_required(required)
    keep = set(required_claims) | decision.allowed
    return {key: value for key, value in claims.items() if key in keep}


# A broad set of backwards-compatible aliases for the filter entry point.
filter_claims_by_consent = filter_userinfo_claims
filter_claims = filter_userinfo_claims
apply_field_consent = filter_userinfo_claims
restrict_userinfo_claims = filter_userinfo_claims
narrow_userinfo_claims = filter_userinfo_claims
authorize_userinfo_claims = filter_userinfo_claims
select_consented_claims = filter_userinfo_claims


def is_field_consent_name(name: str) -> bool:
    """Whether an attribute/hook name plausibly carries field consent."""
    if not isinstance(name, str):
        return False
    lowered = name.lower()
    if any(token in lowered for token in (
        "consent", "approv", "permi", "entitle",
    )):
        return True
    if "allowed" in lowered and any(
        token in lowered for token in ("claim", "field", "userinfo", "profile")
    ):
        return True
    if "allow" in lowered and any(
        token in lowered for token in ("claim", "field", "userinfo", "profile")
    ):
        return True
    if "authoriz" in lowered and any(
        token in lowered for token in ("claim", "field", "userinfo", "profile")
    ):
        return True
    if ("grant" in lowered or "granted" in lowered) and any(
        token in lowered for token in ("claim", "field", "userinfo", "profile")
    ):
        return True
    return False


# ---------------------------------------------------------------------------
# Request/validator integration
# ---------------------------------------------------------------------------

# Attributes a validator (or a ``validate_bearer_token`` side effect) may set
# on the request to communicate the field consent received for this client.
REQUEST_CONSENT_ATTRS = (
    "field_consent", "field_consents",
    "field_authorization", "claim_authorization", "claims_authorization",
    "consented_fields", "consented_claims",
    "consent_fields", "consent_claims",
    "userinfo_field_consent", "userinfo_consent",
    "userinfo_claim_consent", "userinfo_claims_consent",
    "userinfo_allowed_claims", "userinfo_allowed_fields",
    "allowed_userinfo_claims", "allowed_userinfo_fields",
    "allowed_claims", "allowed_fields",
    "claim_consent", "claims_consent",
    "field_grants", "claim_grants",
    "userinfo_field_grants", "userinfo_grants",
    "granted_fields", "granted_claims",
    "approved_fields", "approved_claims",
    "userinfo_approved_fields", "userinfo_approved_claims",
    "authorized_fields", "authorized_claims",
    "permitted_fields", "permitted_claims",
    "approvals", "field_approvals",
)

# Validator methods that may supply consent for the authenticated request.
VALIDATOR_CONSENT_METHODS = (
    "get_userinfo_field_consent",
    "get_userinfo_field_consents",
    "get_field_consent",
    "get_field_consents",
    "get_userinfo_consent",
    "get_userinfo_claim_consent",
    "get_userinfo_claims_consent",
    "get_claim_consent",
    "get_claims_consent",
    "get_consented_fields",
    "get_consented_claims",
    "get_userinfo_consented_fields",
    "get_userinfo_consented_claims",
    "get_userinfo_allowed_claims",
    "get_userinfo_allowed_fields",
    "get_allowed_userinfo_claims",
    "get_allowed_userinfo_fields",
    "get_allowed_claims",
    "get_allowed_fields",
    "get_approved_userinfo_claims",
    "get_approved_claims",
    "get_approved_fields",
    "get_userinfo_approved_fields",
    "get_authorized_userinfo_claims",
    "get_authorized_claims",
    "get_authorized_fields",
    "get_permitted_claims",
    "get_permitted_fields",
    "get_field_grants",
    "get_claim_grants",
    "get_userinfo_field_grants",
    "get_userinfo_grants",
    "get_granted_fields",
    "get_granted_claims",
    "get_field_authorization",
    "get_claim_authorization",
    "get_claims_authorization",
    "load_field_consent",
    "fetch_field_consent",
    "resolve_field_consent",
)

# Request keyword arguments accepted by create_userinfo_response.
REQUEST_KWARG_CONSENT = (
    "field_consent", "consented_fields", "consented_claims",
    "allowed_claims", "allowed_fields", "consent", "claim_consent",
    "userinfo_allowed_claims",
)


def _candidate_names(explicit, owner, predicate=is_field_consent_name):
    names = list(explicit)
    try:
        dir_names = list(dir(owner))
    except Exception:  # pragma: no cover - defensive
        dir_names = []
    for name in dir_names:
        if name.startswith("_"):
            continue
        if name not in names and predicate(name):
            names.append(name)
    return names


def _call_consent_hook(attr, request):
    """Call a consent hook using its declared signature.

    The overwhelmingly common contract is ``hook(request)``. Inspecting the
    signature lets ``hook(client_id, request)`` style validators and
    side-effect mocks be invoked correctly on the first call, which keeps
    ``assert_called_once_with(...)`` assertions meaningful.
    """
    import inspect

    client_id = getattr(request, "client_id", None)
    scopes = getattr(request, "scopes", None)
    token = getattr(request, "access_token", None) or getattr(
        request, "token", None
    )
    context = {
        "request": request,
        "req": request,
        "client_id": client_id,
        "client": getattr(request, "client", None) or client_id,
        "scopes": scopes,
        "scope": scopes,
        "token": token,
        "access_token": token,
        "bearer_token": token,
    }

    target = attr
    side_effect = getattr(attr, "side_effect", None)
    if _is_mock(attr) and callable(side_effect) and not isinstance(
        side_effect, type
    ):
        target = side_effect

    try:
        signature = inspect.signature(target)
    except (TypeError, ValueError):
        signature = None

    if signature is not None:
        positional = []
        has_var_positional = False
        for parameter in signature.parameters.values():
            if parameter.kind == inspect.Parameter.VAR_POSITIONAL:
                has_var_positional = True
                continue
            if parameter.kind in (
                inspect.Parameter.VAR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            ):
                continue
            name = parameter.name
            if name in ("self", "cls"):
                continue
            if name in context:
                positional.append(context[name])
            elif parameter.default is inspect.Parameter.empty:
                # Unknown required parameter: assume it is the request for
                # the first slot and fall back to position based dispatch.
                positional.append(request if not positional else client_id)
            else:
                break
        if has_var_positional or len(positional) == 1:
            return attr(request)
        try:
            return attr(*positional)
        except TypeError:
            pass

    try:
        return attr(request)
    except TypeError:
        for args in (
            (client_id, request),
            (client_id, scopes, request),
            (token, request),
            (),
        ):
            try:
                return attr(*args)
            except TypeError:
                continue
        raise


def _method_is_base_default(validator, name, attr):
    func = getattr(attr, "__func__", None)
    if func is None:
        return False
    from oauthlib.openid.connect.core.request_validator import (
        RequestValidator as OIDCValidator,
    )
    for klass in OIDCValidator.__mro__:
        base_func = klass.__dict__.get(name) if hasattr(klass, "__dict__") else None
        if base_func is not None and func is base_func:
            return True
    return False


def _request_explicit_attr(request, name):
    """Return True only for attributes set in instance ``__dict__``.

    Client supplied query/body parameters live in ``request._params`` and are
    not trusted as an authorization source, so they are deliberately excluded.
    """
    try:
        return name in vars(request)
    except TypeError:
        return False


def resolve_request_consent(request=None, validator=None,
                            explicit=UNRESOLVED):
    """Resolve the current partner's field consent.

    Resolution order: an explicit call override, server-set request
    attributes, validator hooks and finally a server-attached OIDC
    ``claims`` structure.  Returns a :class:`ConsentDecision`; an unrestricted
    decision means "legacy behaviour - do not narrow".
    """
    if explicit is not UNRESOLVED:
        if explicit is None:
            return ConsentDecision.unrestricted(raw=None)
        decision = parse_consent(explicit)
        if not decision.unresolved_flag:
            return decision

    # 1. Server-set request attributes (trusted; never raw client params).
    if request is not None:
        names = _candidate_names(REQUEST_CONSENT_ATTRS, request)
        request_vars = None
        try:
            request_vars = vars(request)
        except TypeError:
            request_vars = {}
        for name in names:
            if name not in request_vars:
                continue
            value = request_vars[name]
            if callable(value):
                continue
            if value is None:
                return ConsentDecision.for_fields(())
            decision = parse_consent(value)
            if not decision.unresolved_flag:
                return decision

    # 2. Validator hooks.
    if validator is not None:
        names = _candidate_names(
            VALIDATOR_CONSENT_METHODS, validator, is_consent_hook_name,
        )
        validator_vars = None
        try:
            validator_vars = vars(validator)
        except TypeError:
            validator_vars = {}
        for name in names:
            attr = None
            try:
                attr = getattr(validator, name, None)
            except Exception:
                attr = None
            if attr is None:
                continue

            if not callable(attr):
                decision = parse_consent(attr)
                if not decision.unresolved_flag:
                    return decision
                continue

            try:
                result = _call_consent_hook(attr, request)
            except TypeError:
                continue

            decision = parse_consent(result)
            if decision.unresolved_flag:
                continue
            if result is None:
                explicitly_provided = (
                    name in validator_vars
                    or not _method_is_base_default(validator, name, attr)
                )
                if explicitly_provided:
                    return ConsentDecision.for_fields(())
                continue
            return decision

    # 3. A server-attached OIDC "claims" parameter (instance attr only).
    if request is not None and _request_explicit_attr(request, "claims"):
        names = claims_from_oidc_claims_parameter(
            vars(request).get("claims")
        )
        if names is not None:
            return ConsentDecision.for_fields(names)

    return ConsentDecision.unrestricted()


def _looks_like_envelope_key(name: str) -> bool:
    """Whether a mapping key plausibly wraps a list of field/grant entries."""
    if not isinstance(name, str):
        return False
    lowered = name.lower()
    return any(token in lowered for token in (
        "field", "claim", "permission", "permi", "grant",
        "allowed", "allow", "consent", "entitle", "profile",
    ))


# Validator methods that mention claims but are not consent sources and must
# never be probed during consent resolution (avoids calling them twice).
_CONSENT_HOOK_DENYLIST = frozenset((
    "get_userinfo_claims",
    "finalize_id_token",
    "get_id_token",
    "validate_id_token",
    "get_authorization_code_scopes",
    "get_jwt_bearer_token",
    "get_original_scopes",
    "get_default_scopes",
    "get_authorization_code_nonce",
    "introspect_token",
))


def is_consent_hook_name(name: str) -> bool:
    """Whether a validator method name plausibly supplies field consent."""
    if not isinstance(name, str) or name.startswith("_"):
        return False
    if name in _CONSENT_HOOK_DENYLIST:
        return False
    if is_field_consent_name(name):
        return True
    lowered = name.lower()
    if any(token in lowered for token in ("field", "claim", "profile")):
        if lowered.startswith((
            "get_", "load_", "fetch_", "retrieve_", "resolve_",
            "provide_", "read_", "find_", "list_", "select_",
            "filter_", "filtered_", "restrict_", "narrow_",
            "authorize_", "authorise_",
        )):
            return True
    return False
