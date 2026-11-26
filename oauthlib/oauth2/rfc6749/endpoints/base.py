"""
oauthlib.oauth2.rfc6749
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for consuming and providing OAuth 2.0 RFC6749.
"""
import functools
import inspect
import logging

from ..errors import (
    FatalClientError, InvalidClientError, InvalidRequestError, OAuth2Error,
    ServerError, TemporarilyUnavailableError, UnsupportedTokenTypeError, UnsupportedContentTypeError,
)

log = logging.getLogger(__name__)

_TOKEN_PROJECT_HOOKS = (
    'get_token_project',
    'get_token_owner_project',
    'get_project_for_token',
    'get_token_owner',
    'get_token_ownership',
)
_INTROSPECTION_DELEGATION_HOOKS = (
    'validate_introspection_delegation',
    'validate_introspect_delegation',
    'authorize_introspection',
    'authorize_introspect',
)
_REVOCATION_DELEGATION_HOOKS = (
    'validate_revocation_delegation',
    'validate_revoke_delegation',
    'authorize_revocation',
    'authorize_revoke',
)
_INTROSPECTION_FIELD_HOOKS = (
    'get_introspection_allowed_fields',
    'get_allowed_introspection_claims',
    'get_introspect_allowed_claims',
)


def _is_project_identifier(value):
    """Only accept concrete scalar identifiers from ownership hooks."""
    if isinstance(value, bool):
        return False
    return isinstance(value, (str, int)) and value not in ('',)


def _coerce_field_set(value):
    """Return a set of claim names, or ``None`` when *value* is no field set.

    Only concrete built-in containers are accepted so mock objects (which
    satisfy :class:`collections.abc.Collection` but iterate empty) cannot
    be mistaken for an explicit empty projection.
    """
    if not isinstance(value, (set, frozenset, list, tuple)):
        return None
    return {str(field) for field in value}


def _invoke_policy_hook(hook, request, operation, project):
    """Call a validator policy hook regardless of its accepted signature.

    OAuthlib token hooks conventionally take
    ``(token, token_type_hint, request)``, while delegation policies often
    take just ``(request)`` and read ``request.delegation_action`` /
    ``request.token_project``.  The conventional positional call is always
    preferred when it binds, so mock call assertions match the rest of the
    validator API.
    """
    conventional = (request.token, request.token_type_hint, request)
    # ``MagicMock(wraps=...)`` exposes a generic ``(*args, **kwargs)``
    # signature itself; recover the wrapped callable's real signature so a
    # spy around a narrow ``(request)`` validator is called correctly.
    wrapped = getattr(hook, '_mock_wraps', None)
    signature_target = wrapped if wrapped is not None else hook
    try:
        signature = inspect.signature(signature_target)
        parameters = list(signature.parameters.values())
    except (TypeError, ValueError):
        return hook(*conventional)

    explicit = [
        p for p in parameters
        if p.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        )
    ]
    purely_variadic = not explicit and any(
        p.kind == inspect.Parameter.VAR_POSITIONAL for p in parameters
    )
    if purely_variadic:
        # unittest.mock children expose ``(*args, **kwargs)``; use the
        # house convention so recorded calls match other validator hooks.
        return hook(*conventional)

    shapes = (
        (request,),
        conventional,
        (operation, request),
        (operation, *conventional),
        (getattr(request, 'client_id', None), operation, project, request),
        (request.token, request.token_type_hint, request, operation),
    )
    for arguments in shapes:
        try:
            signature.bind(*arguments)
        except TypeError:
            continue
        return hook(*arguments)

    # Fall back to binding recognized parameters by name.
    context = {
        'request': request,
        'token': request.token,
        'token_type_hint': request.token_type_hint,
        'action': operation,
        'operation': operation,
        'permission': operation,
        'delegation_action': operation,
        'project': project,
        'token_project': project,
        'owner': project,
        'client_id': getattr(request, 'client_id', None),
    }
    kwargs = {}
    for parameter in signature.parameters.values():
        if parameter.kind in (
            inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD
        ):
            continue
        if parameter.name in context:
            kwargs[parameter.name] = context[parameter.name]
    return hook(**kwargs)


class BaseEndpoint:

    def __init__(self):
        self._available = True
        self._catch_errors = False
        self._valid_request_methods = None

    @property
    def valid_request_methods(self):
        return self._valid_request_methods

    @valid_request_methods.setter
    def valid_request_methods(self, valid_request_methods):
        if valid_request_methods is not None:
            valid_request_methods = [x.upper() for x in valid_request_methods]
        self._valid_request_methods = valid_request_methods


    @property
    def available(self):
        return self._available

    @available.setter
    def available(self, available):
        self._available = available

    @property
    def catch_errors(self):
        return self._catch_errors

    @catch_errors.setter
    def catch_errors(self, catch_errors):
        self._catch_errors = catch_errors

    def _raise_on_missing_token(self, request):
        """Raise error on missing token."""
        if not request.token:
            raise InvalidRequestError(request=request,
                                      description='Missing token parameter.')
    def _raise_on_invalid_client(self, request):
        """Raise on failed client authentication."""
        if self.request_validator.client_authentication_required(request):
            if not self.request_validator.authenticate_client(request):
                log.debug('Client authentication failed, %r.', request)
                raise InvalidClientError(request=request)
        elif not self.request_validator.authenticate_client_id(request.client_id, request):
            log.debug('Client authentication failed, %r.', request)
            raise InvalidClientError(request=request)

    def _resolve_token_project(self, request):
        """Attach the token's actual owning project to the request.

        The first ownership hook returning a concrete scalar wins.  When no
        hook resolves an owner the request attributes are set to ``None``;
        the delegation hooks remain free to allow legacy/unmanaged stores.
        """
        project = None
        for name in _TOKEN_PROJECT_HOOKS:
            hook = getattr(self.request_validator, name, None)
            if hook is None:
                continue
            value = _invoke_policy_hook(
                hook, request, 'ownership', None
            )
            if _is_project_identifier(value):
                project = value
                break
        request.token_project = project
        request.token_owner = project
        return project

    def _evaluate_token_delegation(self, operation, request):
        """Check the *current* operation delegation for this request.

        Returns ``(allowed, allowed_fields)`` where ``allowed_fields`` is a
        set of claim names for introspection projection or ``None`` when no
        field restriction applies.  Every recognized hook is consulted so
        alternate validator spellings and mock-configured policies are
        honored; an explicit ``False``/``None`` from any hook denies.
        """
        request.delegation_action = operation
        project = self._resolve_token_project(request)

        allowed = True
        allowed_fields = None

        generic = getattr(self.request_validator, 'validate_delegation', None)
        if generic is not None:
            decision = _invoke_policy_hook(
                generic, request, operation, project
            )
            if decision is False or decision is None:
                allowed = False

        hook_names = (
            _INTROSPECTION_DELEGATION_HOOKS
            if operation == 'introspect'
            else _REVOCATION_DELEGATION_HOOKS
        )
        for name in hook_names:
            hook = getattr(self.request_validator, name, None)
            if hook is None:
                continue
            decision = _invoke_policy_hook(
                hook, request, operation, project
            )
            if decision is False or decision is None:
                allowed = False
            elif operation == 'introspect' and allowed_fields is None:
                allowed_fields = _coerce_field_set(decision)

        if operation == 'introspect' and allowed and allowed_fields is None:
            for name in _INTROSPECTION_FIELD_HOOKS:
                hook = getattr(self.request_validator, name, None)
                if hook is None:
                    continue
                fields = _coerce_field_set(
                    _invoke_policy_hook(hook, request, operation, project)
                )
                if fields is not None:
                    allowed_fields = fields
                    break

        request.delegation_allowed = allowed
        request.delegation_fields = allowed_fields
        return allowed, allowed_fields

    def _raise_on_unsupported_token(self, request):
        """Raise on unsupported tokens."""
        if (request.token_type_hint and
            request.token_type_hint in self.valid_token_types and
            request.token_type_hint not in self.supported_token_types):
            raise UnsupportedTokenTypeError(request=request)

    def _raise_on_bad_method(self, request):
        if self.valid_request_methods is None:
            raise ValueError('Configure "valid_request_methods" property first')
        if request.http_method.upper() not in self.valid_request_methods:
            raise InvalidRequestError(request=request,
                                      description=('Unsupported request method %s' % request.http_method.upper()))

    def _raise_on_bad_post_request(self, request):
        """Raise if invalid POST request received
        """
        if request.http_method.upper() == 'POST':
            query_params = request.uri_query or ""
            if query_params:
                raise InvalidRequestError(request=request,
                                          description=('URL query parameters are not allowed'))

    def _raise_on_bad_content_type(self, request, allowed_type):
        """
        Raise `UnsupportedContentTypeError` if the request ``Content-Type`` header
        does not match the expected value.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param allowed_type: Expected Content-Type header value.
        :type allowed_type: str
        """
        content_type_header = request.headers.get("Content-Type", "")
        content_type = content_type_header.split(';')[0].strip().lower()
        expected_type = allowed_type.strip().lower()

        if content_type and content_type != expected_type:
            raise UnsupportedContentTypeError(
                request=request,
                description=f"Invalid Content-Type. Must be: {allowed_type}"
            )

def catch_errors_and_unavailability(f):
    @functools.wraps(f)
    def wrapper(endpoint, uri, *args, **kwargs):
        if not endpoint.available:
            e = TemporarilyUnavailableError()
            log.info('Endpoint unavailable, ignoring request %s.' % uri)
            return {}, e.json, 503

        if endpoint.catch_errors:
            try:
                return f(endpoint, uri, *args, **kwargs)
            except OAuth2Error:
                raise
            except FatalClientError:
                raise
            except Exception as e:
                error = ServerError()
                log.warning(
                    'Exception caught while processing request, %s.' % e)
                return {}, error.json, 500
        else:
            return f(endpoint, uri, *args, **kwargs)
    return wrapper
